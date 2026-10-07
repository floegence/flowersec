import { randomBytes } from "node:crypto";
import { Cookie, CookieJar } from "tough-cookie";
import type { V4TransportEnvironment } from "../v4/public.js";
import type { V4CleanupStatus } from "../generated/transportV4APIResults.js";
import { originalEnvironment } from "../v4/runtime/environment.js";
import { ResourceVector, type ResourceAccount, type ResourceReference } from "../v4/runtime/resources.js";
import { credentialOwner } from "../v4/runtime/credentialSupport.js";
import { TrustedDeadline, timerChunk } from "../v4/runtime/deadline.js";
import type { ProxyCredentialControlRequest, ProxyCredentialControlResponse } from "../proxy/credentialControl.js";
import { PROXY_WIRE_VERSION } from "../proxy/wire.js";
import type { ProxyHeader } from "../proxy/types.js";

export interface ProxyCredentialAuthentication {
  readonly tenant: string; readonly audience: string; readonly localRole: string;
  readonly localSubject: string; readonly peerSubject: string; readonly peerIdentityDigest: string;
}
export interface ProxyCookieScope {
  readonly tenant: string;
  readonly principal: string;
  readonly policyRevision: string;
  readonly surfaceOwner: string;
  readonly contentOrigin: string;
  readonly scopeNotAfterMS: bigint;
  readonly idleMS: bigint;
  readonly delegatedFirstParty: true;
}
export type ProxyCredentialPolicy = Readonly<{ mode: "none" }> | Readonly<{
  mode: "external";
  external(authentication: ProxyCredentialAuthentication, target: URL, signal: AbortSignal): Promise<readonly ProxyHeader[]>;
}> | Readonly<{
  mode: "upstream_cookie_session";
  environment: V4TransportEnvironment;
  /** Existing complete ProxyServer pool scopes; Cookie limits allocate no new account. */
  proxyAccounts: readonly ResourceAccount[];
  profile?: "ordinary" | "constrained";
  maxOwners?: number;
  maxCookieBytes?: bigint;
  allowWebSocket?: boolean;
  /** Resolves trusted scope from the original authenticated Stream. Each Surface
   * receives its own jar. No implicit borrower or cross-Surface sharing exists. */
  resolveScope(surfaceOwner: string, authentication: ProxyCredentialAuthentication, signal: AbortSignal): Promise<ProxyCookieScope>;
  authorize(authentication: ProxyCredentialAuthentication, scope: ProxyCookieScope, action: "request" | "clear" | "dispose"): boolean;
}>;
class CredentialFailure extends Error {
  constructor(readonly code: "credential_scope_unavailable" | "credential_update_failed") { super(code); }
}
function fail(): never { throw new CredentialFailure("credential_scope_unavailable"); }
function trustedOrigin(value: string): boolean { try { const url = new URL(value); return url.origin === value && ["http:", "https:"].includes(url.protocol); } catch { return false; } }
function date(value: bigint): Date { if (value < 0n || value > 8640000000000000n) fail(); return new Date(Number(value)); }
function charge(bytes: bigint): ResourceVector { return new ResourceVector([bytes, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]); }
interface CookieOwner {
  readonly scope: ProxyCookieScope;
  readonly deadline: TrustedDeadline;
  context: string;
  incarnation: bigint;
  lastUpperMS: bigint;
  jar: CookieJar;
  state: ResourceReference;
  stateBytes: bigint;
  readonly active: Set<AbortController>;
  closed: boolean;
  timer?: ReturnType<typeof setTimeout> | undefined;
  lastControl?: ProxyCredentialControlResponse;
  bindOperation?: string;
  bindContext?: string;
  previousContext?: string;
}
export interface ProxyCredentialRequest {
  readonly signal: AbortSignal;
  readonly managed: boolean;
  headers: readonly ProxyHeader[];
  check(): void;
  update(headers: readonly ProxyHeader[], target: URL): readonly ProxyHeader[];
  close(): void;
}
/** Volatile credentials use the same original Environment accounts as request
 * admission. The cookie limits are sublimits, never additional allowances. */
export class ProxyCredentialManager {
  readonly #policy: ProxyCredentialPolicy;
  readonly #upstream: URL;
  readonly #owners = new Map<string, CookieOwner>();
  readonly #surfaces = new Map<string, CookieOwner>();
  #bytes = 0n;
  #closed = false;
  constructor(policy: ProxyCredentialPolicy | undefined, upstream: URL) {
    this.#policy = policy === undefined ? Object.freeze({ mode: "none" }) : Object.freeze({ ...policy,
      ...(policy.mode === "upstream_cookie_session" ? { proxyAccounts: Object.freeze([...policy.proxyAccounts]) } : {}) }); this.#upstream = new URL(upstream.origin);
    if (policy?.mode === "upstream_cookie_session") {
      originalEnvironment(policy.environment);
      const maxOwners = policy.maxOwners ?? (policy.profile === "constrained" ? 16 : 64), maxBytes = policy.maxCookieBytes ?? (policy.profile === "constrained" ? 2n << 20n : 8n << 20n);
      if (!Number.isSafeInteger(maxOwners) || maxOwners < 1 || maxOwners > (policy.profile === "constrained" ? 16 : 64) || maxBytes < 65536n || maxBytes > (policy.profile === "constrained" ? 2n << 20n : 8n << 20n) ||
          !Array.isArray(policy.proxyAccounts) || policy.proxyAccounts.length < 1 || policy.proxyAccounts.length > 4 ||
          typeof policy.resolveScope !== "function" || typeof policy.authorize !== "function") fail();
    }
  }
  #reserve(bytes: bigint): ResourceReference {
    const policy = this.#policy; if (policy.mode !== "upstream_cookie_session") fail();
    if (bytes > (policy.maxCookieBytes ?? (policy.profile === "constrained" ? 2n << 20n : 8n << 20n)) - this.#bytes) throw new CredentialFailure("credential_update_failed");
    const resources = originalEnvironment(policy.environment).resources;
    const ref = resources.root.reserve({ owner: credentialOwner(resources, "proxy_cookies"), accounts: [...resources.accounts, ...policy.proxyAccounts], charge: charge(bytes) });
    this.#bytes += bytes; return ref;
  }
  #release(ref: ResourceReference, bytes: bigint): void { ref.release(); this.#bytes -= bytes; }
  #sample(owner: CookieOwner): Readonly<{ lowerMS: bigint; upperMS: bigint }> {
    if (this.#closed || owner.closed) fail(); owner.state.check(); owner.deadline.check();
    const now = owner.deadline.sample().requireInterval();
    if (now.upperMS >= owner.scope.scopeNotAfterMS || now.upperMS < owner.lastUpperMS ||
        now.upperMS - owner.lastUpperMS >= owner.scope.idleMS) { this.#retire(owner); fail(); }
    return now;
  }
  #schedule(owner: CookieOwner): void {
    if (owner.timer !== undefined) clearTimeout(owner.timer);
    if (owner.closed) return;
    let remaining: bigint;
    try {
      const now = this.#sample(owner), idleEnd = owner.lastUpperMS + owner.scope.idleMS;
      const end = idleEnd < owner.scope.scopeNotAfterMS ? idleEnd : owner.scope.scopeNotAfterMS;
      remaining = end > now.upperMS ? end - now.upperMS : 0n;
    } catch { this.#retire(owner); return; }
    owner.timer = setTimeout(() => { owner.timer = undefined; this.#schedule(owner); }, timerChunk(remaining));
  }
  #retire(owner: CookieOwner): void {
    if (owner.closed) return; owner.closed = true;
    if (owner.timer !== undefined) clearTimeout(owner.timer); owner.timer = undefined; this.#owners.delete(owner.context);
    for (const active of owner.active) active.abort(new Error("credential_scope_unavailable"));
    this.#collect(owner);
  }
  #collect(owner: CookieOwner): void {
    if (!owner.closed || owner.active.size !== 0 || owner.stateBytes === 0n) return;
    this.#surfaces.delete(owner.scope.surfaceOwner); this.#release(owner.state, owner.stateBytes); owner.stateBytes = 0n;
    owner.jar = new CookieJar(undefined, { rejectPublicSuffixes: true, prefixSecurity: "strict", allowSpecialUseDomain: false });
  }
  async control(request: ProxyCredentialControlRequest, authentication: ProxyCredentialAuthentication | undefined,
    signal: AbortSignal): Promise<ProxyCredentialControlResponse> {
    const policy = this.#policy;
    if (this.#closed || policy.mode !== "upstream_cookie_session" || authentication === undefined) fail();
    signal.throwIfAborted();
    if (request.action === 1) {
      const existing = this.#surfaces.get(request.surface_owner);
      if (existing !== undefined && existing.bindOperation === request.operation_id && existing.scope.contentOrigin === request.content_origin &&
          existing.scope.tenant === authentication.tenant && existing.scope.principal === authentication.peerSubject && policy.authorize(authentication, existing.scope, "request")) {
        this.#sample(existing); return Object.freeze({ v: PROXY_WIRE_VERSION, operation_id: request.operation_id, action: 1, ok: true, credential_context: existing.bindContext! });
      }
      if (this.#surfaces.has(request.surface_owner) || this.#surfaces.size >= (policy.maxOwners ?? (policy.profile === "constrained" ? 16 : 64))) fail();
      const scope = Object.freeze({ ...await policy.resolveScope(request.surface_owner, authentication, signal) }); signal.throwIfAborted();
      if (!scope.delegatedFirstParty || scope.surfaceOwner !== request.surface_owner || scope.contentOrigin !== request.content_origin ||
          !trustedOrigin(scope.contentOrigin) || scope.tenant !== authentication.tenant || scope.principal !== authentication.peerSubject ||
          scope.policyRevision === "" || typeof scope.idleMS !== "bigint" || scope.idleMS < 1n || !policy.authorize(authentication, scope, "request")) fail();
      if (this.#closed || this.#surfaces.has(request.surface_owner) || this.#surfaces.size >= (policy.maxOwners ?? (policy.profile === "constrained" ? 16 : 64))) fail();
      const environment = originalEnvironment(policy.environment), deadline = new TrustedDeadline(environment.clock, scope.scopeNotAfterMS);
      deadline.check(); const now = deadline.sample().requireInterval(), stateBytes = 65536n;
      const state = this.#reserve(stateBytes), context = randomBytes(32).toString("base64url");
      const owner: CookieOwner = { scope, deadline, context, incarnation: 1n, lastUpperMS: now.upperMS,
        jar: new CookieJar(undefined, { rejectPublicSuffixes: true, prefixSecurity: "strict", allowSpecialUseDomain: false }),
        state, stateBytes, active: new Set(), closed: false, bindOperation: request.operation_id, bindContext: context };
      this.#owners.set(context, owner); this.#surfaces.set(scope.surfaceOwner, owner); this.#schedule(owner);
      return Object.freeze({ v: PROXY_WIRE_VERSION, operation_id: request.operation_id, action: 1, ok: true, credential_context: context });
    }
    const original = this.#surfaces.get(request.surface_owner);
    if (request.action === 2 && original !== undefined && original.previousContext === request.credential_context && original.lastControl?.operation_id === request.operation_id &&
        original.scope.tenant === authentication.tenant && original.scope.principal === authentication.peerSubject && policy.authorize(authentication, original.scope, "clear")) {
      this.#sample(original); return original.lastControl;
    }
    const owner = this.#owners.get(request.credential_context!);
    if (owner === undefined || owner.scope.tenant !== authentication.tenant || owner.scope.principal !== authentication.peerSubject || owner.scope.surfaceOwner !== request.surface_owner || !policy.authorize(authentication, owner.scope,
      request.action === 2 ? "clear" : "dispose")) fail();
    this.#sample(owner); signal.throwIfAborted();
    if (request.action === 3) {
      this.#retire(owner);
      return Object.freeze({ v: PROXY_WIRE_VERSION, operation_id: request.operation_id, action: 3, ok: true, server_invalidated: true });
    }
    if (owner.incarnation === 0xffffffffffffffffn) {
      this.#retire(owner);
      return Object.freeze({ v: PROXY_WIRE_VERSION, operation_id: request.operation_id, action: 2, ok: false, server_invalidated: true,
        error: Object.freeze({ code: "credential_update_failed", message: "credential association unavailable" }) });
    }
    // Revocation commits independently of next-association allocation. Existing
    // native requests hold their own copies and are canceled before any reuse.
    const oldContext = owner.context;
    this.#owners.delete(oldContext); owner.incarnation++; owner.previousContext = oldContext;
    for (const active of owner.active) active.abort(new Error("credential_scope_unavailable"));
    let state: ResourceReference | undefined;
    try {
      const stateBytes = 65536n; state = this.#reserve(stateBytes);
      const context = randomBytes(32).toString("base64url"), jar = new CookieJar(undefined,
        { rejectPublicSuffixes: true, prefixSecurity: "strict", allowSpecialUseDomain: false });
      const previous = owner.state, previousBytes = owner.stateBytes;
      owner.context = context; owner.jar = jar; owner.state = state; owner.stateBytes = stateBytes;
      this.#owners.set(context, owner); this.#release(previous, previousBytes);
      const ack = Object.freeze({ v: PROXY_WIRE_VERSION, operation_id: request.operation_id, action: 2 as const, ok: true,
        credential_context: context, server_invalidated: true }); owner.lastControl = ack; return ack;
    } catch {
      if (state !== undefined) this.#release(state, 65536n);
      this.#retire(owner);
      return Object.freeze({ v: PROXY_WIRE_VERSION, operation_id: request.operation_id, action: 2, ok: false, server_invalidated: true,
        error: Object.freeze({ code: "credential_update_failed", message: "credential association unavailable" }) });
    }

  }
  async capture(input: Readonly<{ credential_context?: string; credentials?: string; request_origin?: string }>,
    authentication: ProxyCredentialAuthentication | undefined, target: URL, fields: readonly ProxyHeader[], parent: AbortSignal, originalFields = fields): Promise<ProxyCredentialRequest> {
    const policy = this.#policy;
    const clean = fields.filter(field => !["cookie", "authorization"].includes(field.name.toLowerCase()));
    if (this.#closed) fail();
    if (policy.mode === "none") {
      if (input.credential_context !== undefined) fail(); return this.#unmanaged(clean, parent);
    }
    if (authentication === undefined) fail();
    if (policy.mode === "external") {
      if (input.credential_context !== undefined) fail();
      const external = await policy.external(authentication, target, parent); parent.throwIfAborted();
      if (external.some(field => !["cookie", "authorization"].includes(field.name.toLowerCase()) || /[^\x09\x20-\x7e\x80-\xff]/u.test(field.value))) fail();
      return this.#unmanaged([...clean, ...external], parent);
    }
    if (originalFields.some(field => ["cookie", "authorization"].includes(field.name.toLowerCase())) ||
        !["omit", "same-origin", "include"].includes(input.credentials ?? "")) fail();
    const owner = this.#owners.get(input.credential_context ?? "");
    if (owner === undefined || owner.scope.tenant !== authentication.tenant || owner.scope.principal !== authentication.peerSubject ||
        !policy.authorize(authentication, owner.scope, "request")) fail();
    const ws = target.protocol === "ws:" || target.protocol === "wss:", expected = ws ? this.#upstream.protocol === "https:" ? "wss:" : "ws:" : this.#upstream.protocol;
    if (target.host !== this.#upstream.host || target.protocol !== expected || ws && policy.allowWebSocket !== true) fail();
    if (input.credentials === "same-origin" && !trustedOrigin(input.request_origin ?? "")) fail();
    const now = this.#sample(owner), incarnation = owner.incarnation;
    const allow = input.credentials === "include" || input.credentials === "same-origin" && input.request_origin === owner.scope.contentOrigin;
    // Selection uses the conservative upper bound; expiry uses no ambient Date.
    const url = new URL(target); if (ws) url.protocol = url.protocol === "wss:" ? "https:" : "http:";
    const requestReserveBytes = owner.stateBytes + 65536n;
    const ref = this.#reserve(requestReserveBytes);
    let selected: Cookie[];
    try { selected = allow ? owner.jar.getCookiesSync(url.href, { expire: false, sameSiteContext: "strict", http: true }).filter(cookie => {
      const expiry = cookie.expiryTime(date(now.upperMS));
      return expiry === Infinity || expiry !== undefined && expiry > Number(now.upperMS);
    }) : []; } catch (error) { this.#release(ref, requestReserveBytes); throw error; }
    const cookie = selected.map(value => value.cookieString()).join("; ");
    const bytes = 16384n + BigInt(cookie.length * 2 + selected.length * 512);
    if (bytes > requestReserveBytes) { this.#release(ref, requestReserveBytes); fail(); }
    ref.shrink(charge(bytes)); this.#bytes -= requestReserveBytes - bytes;
    const controller = new AbortController(), canceled = () => controller.abort(parent.reason);
    parent.addEventListener("abort", canceled, { once: true }); if (parent.aborted) canceled(); owner.active.add(controller);
    owner.lastUpperMS = now.upperMS; this.#schedule(owner);
    let closed = false;
    const check = (): void => { if (closed || controller.signal.aborted || owner.incarnation !== incarnation) fail(); ref.check(); this.#sample(owner); };
    return Object.freeze<ProxyCredentialRequest>({ signal: controller.signal, managed: true,
      headers: Object.freeze(cookie === "" ? clean : [...clean, { name: "cookie", value: cookie }]), check,
      update: (headers, actualTarget) => { check(); return this.#update(owner, incarnation, allow, headers, actualTarget); },
      close: () => { if (closed) return; closed = true; parent.removeEventListener("abort", canceled); owner.active.delete(controller); this.#release(ref, bytes); this.#collect(owner); },
    });
  }
  #unmanaged(headers: readonly ProxyHeader[], signal: AbortSignal): ProxyCredentialRequest {
    return Object.freeze<ProxyCredentialRequest>({ headers, signal, managed: false, check: () => signal.throwIfAborted(), update: fields => fields, close() {} });
  }
  #update(owner: CookieOwner, incarnation: bigint, allow: boolean, fields: readonly ProxyHeader[], target: URL): readonly ProxyHeader[] {
    const stripped = fields.filter(field => field.name.toLowerCase() !== "set-cookie" && field.name.toLowerCase() !== "cache-control");
    stripped.push({ name: "cache-control", value: "no-store, no-transform" });
    if (!allow) return stripped;
    const lines = fields.filter(field => field.name.toLowerCase() === "set-cookie");
    if (lines.length === 0) return stripped;
    const now = this.#sample(owner);
    if (owner.incarnation !== incarnation || lines.length > 64) throw new CredentialFailure("credential_update_failed");
    const rawBytes = lines.reduce((sum, line) => sum + Math.min(line.value.length, 4096), 0);
    const candidateBytes = owner.stateBytes * 2n + BigInt(rawBytes * 8) + 65536n;
    let candidateRef: ResourceReference;
    try { candidateRef = this.#reserve(candidateBytes); } catch { throw new CredentialFailure("credential_update_failed"); }
    let installed = false;
    try {
      const serialization = owner.jar.serializeSync(); if (serialization === undefined) throw new CredentialFailure("credential_update_failed");
      const candidate = CookieJar.deserializeSync(serialization), url = new URL(target);
      if (url.protocol === "wss:" || url.protocol === "ws:") url.protocol = url.protocol === "wss:" ? "https:" : "http:";
      for (const line of lines) {
        if (line.value.length > 4096) continue;
        const cookie = Cookie.parse(line.value);
        if (cookie === undefined || cookie.extensions?.some(extension => /^partitioned(?:\s|=|$)/iu.test(extension)) ||
            cookie.sameSite === "none" && !cookie.secure || cookie.key.startsWith("__Http-") && (!cookie.httpOnly || !cookie.secure) ||
            cookie.key.startsWith("__Host-Http-") && (!cookie.httpOnly || !cookie.secure || cookie.domain != null || cookie.path !== "/")) continue;
        if (cookie.sameSite === undefined) cookie.sameSite = "lax";
        if (cookie.maxAge !== null) {
          const seconds = typeof cookie.maxAge === "number" ? cookie.maxAge : cookie.maxAge === "Infinity" ? Infinity : -Infinity;
          if (seconds === Infinity) { cookie.expires = date(owner.scope.scopeNotAfterMS); }
          else if (seconds <= 0) cookie.expires = new Date(0);
          else { const cap = now.lowerMS + BigInt(seconds) * 1000n; cookie.expires = date(cap < owner.scope.scopeNotAfterMS ? cap : owner.scope.scopeNotAfterMS); }
          cookie.maxAge = null;
        }
        try { candidate.setCookieSync(cookie, url.href, { now: date(now.lowerMS), http: true, sameSiteContext: "strict" }); }
        catch { /* Fixed profile rejects this individual invalid Cookie. */ }
      }
      const result = candidate.serializeSync();
      if (result === undefined || result.cookies.length > 64) throw new CredentialFailure("credential_update_failed");
      const stateBytes = 65536n + BigInt(JSON.stringify(result).length * 4 + result.cookies.length * 1024);
      if (stateBytes > 512n << 10n || stateBytes > candidateBytes) throw new CredentialFailure("credential_update_failed");
      this.#sample(owner); if (owner.incarnation !== incarnation) fail();
      candidateRef.shrink(charge(stateBytes)); this.#bytes -= candidateBytes - stateBytes;
      const old = owner.state, oldBytes = owner.stateBytes;
      owner.jar = candidate; owner.state = candidateRef; owner.stateBytes = stateBytes; installed = true; this.#release(old, oldBytes);
      return stripped;
    } finally { if (!installed) this.#release(candidateRef, candidateBytes); }
  }
  cleanupStatus(): V4CleanupStatus {
    const count = [...this.#surfaces.values()].reduce((sum, owner) => sum + owner.active.size, 0);
    return Object.freeze({ status: count === 0 ? "complete" : "pending", core_cleanup: count === 0 ? "complete" : "pending", pending_callbacks: BigInt(count) });
  }
  close(): void { if (this.#closed) return; this.#closed = true; for (const owner of [...this.#surfaces.values()]) this.#retire(owner); }
}
