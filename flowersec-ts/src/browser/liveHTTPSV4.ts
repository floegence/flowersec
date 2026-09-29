import type { V4TransportEnvironment } from "../v4/public.js";
import { originalEnvironment } from "../v4/runtime/environment.js";
import { byteLength, byteSlice } from "../v4/runtime/cbor.js";
import { ResourceVector } from "../v4/runtime/resources.js";
import { TrustedDeadline, TrustedWindow, timerChunk } from "../v4/runtime/deadline.js";
import { bindLiveAuthorizationConfig, type V4LiveAuthorizationConfig, type V4LiveAuthorizationProvider } from "../v4/runtime/liveAuthorization.js";
import { encodeLiveAuthorizationRequest } from "../v4/runtime/liveAuthorizationWire.js";

const nativeFetch = globalThis.fetch;
const copy = Uint8Array.prototype.set;
const identifier = /^[a-z0-9][a-z0-9._:/@-]{0,127}$/u;
function requireControl(condition: unknown, code = "control_configuration"): asserts condition {
  if (!condition) throw new Error(code);
}

/** Independently configured operator evidence, never a peer capability claim.
 * The browser-facing terminator (including proxies) enforces TLS 1.3, rejects
 * early data and authenticates the explicitly supplied control credential.
 * Responses use identity encoding without trailers; CORS exposes all response
 * framing headers. Fetch does not reveal the negotiated TLS version. */
export interface V4BrowserLiveHTTPSDeployment {
  readonly deploymentID: string;
  readonly revision: string;
  readonly baseURL: string;
  readonly applicationOrigin: string;
  readonly notBeforeMS: bigint;
  readonly notAfterMS: bigint;
  readonly terminatorProfile: "tls13-no-early-data-authenticated-control";
  readonly evidenceReference: string;
}
export interface V4BrowserLiveHTTPSOptions {
  readonly deployment: V4BrowserLiveHTTPSDeployment;
  readonly authority: string;
  readonly tenant: string;
  readonly audience: string;
  /** Calling credential for the fixed control authority; never an issuer key. */
  readonly bearerToken: string;
  readonly credentialNotAfterMS: bigint;
  readonly maxConcurrentRequests: number;
  readonly timeoutMS: bigint;
  readonly headerBytes: number;
  readonly runtimeBytes: bigint;
  /** Qualified native Fetch/TLS/body allowance; JS cannot cap process memory. */
  readonly providerBytes: bigint;
}

/** One physical Fetch per authorization attempt. Returned bytes are still
 * untrusted until the original credential owner validates the signed proof. */
export function createV4BrowserLiveHTTPS(environment: V4TransportEnvironment, options: V4BrowserLiveHTTPSOptions): V4LiveAuthorizationConfig {
  const owner = originalEnvironment(environment), input = options.deployment;
  requireControl(typeof nativeFetch === "function" && globalThis.isSecureContext && typeof globalThis.location?.origin === "string");
  const { deploymentID, revision, baseURL, applicationOrigin, notBeforeMS, notAfterMS, terminatorProfile, evidenceReference } = input;
  requireControl(typeof deploymentID === "string" && identifier.test(deploymentID) && typeof revision === "string" && identifier.test(revision) && terminatorProfile === "tls13-no-early-data-authenticated-control" &&
    typeof evidenceReference === "string" && evidenceReference.length > 0 && evidenceReference.length <= 1024 &&
    typeof baseURL === "string" && baseURL.length > 0 && baseURL.length <= 2048 && !/[\s%\\?#]/u.test(baseURL));
  let base: URL, origin: URL;
  try { base = new URL(baseURL); origin = new URL(applicationOrigin); } catch { throw new Error("control_configuration"); }
  requireControl(base.protocol === "https:" && base.username === "" && base.password === "" && base.search === "" && base.hash === "" &&
    baseURL.replace(/\/$/u, "") === base.href.replace(/\/$/u, "") && origin.protocol === "https:" &&
    origin.origin === applicationOrigin && applicationOrigin === globalThis.location.origin);
  const { authority, tenant, audience, credentialNotAfterMS, maxConcurrentRequests, timeoutMS, headerBytes, runtimeBytes, providerBytes } = options;
  let bearer: string | undefined = options.bearerToken;
  requireControl(typeof authority === "string" && identifier.test(authority) && typeof tenant === "string" && identifier.test(tenant) && typeof audience === "string" && identifier.test(audience) && typeof bearer === "string" &&
    bearer.length >= 1 && bearer.length <= 8192 && /^[A-Za-z0-9._~+/-]+=*$/u.test(bearer) &&
    typeof notBeforeMS === "bigint" && notBeforeMS >= 0n && typeof notAfterMS === "bigint" && notAfterMS > notBeforeMS && notAfterMS <= 0xffffffffffffffffn &&
    typeof credentialNotAfterMS === "bigint" && credentialNotAfterMS > notBeforeMS && credentialNotAfterMS <= 0xffffffffffffffffn &&
    Number.isSafeInteger(maxConcurrentRequests) && maxConcurrentRequests >= 1 && maxConcurrentRequests <= 64 &&
    typeof timeoutMS === "bigint" && timeoutMS > owner.clock.profile.rate.elapsed(0n).upperMS && timeoutMS <= 90000n &&
    Number.isSafeInteger(headerBytes) && headerBytes >= 1024 && headerBytes <= 65536 &&
    typeof runtimeBytes === "bigint" && runtimeBytes > 0n && typeof providerBytes === "bigint" && providerBytes >= 262144n + BigInt(4 * headerBytes));
  const deadline = new TrustedDeadline(owner.clock, notAfterMS < credentialNotAfterMS ? notAfterMS : credentialNotAfterMS);
  requireControl(owner.clock.sample().requireInterval().lowerMS >= notBeforeMS, "control_expired");
  const endpoint = base.origin + base.pathname.replace(/\/$/u, "") + "/live/authorize";
  const dependency = owner.admitDependency("browser_live_https", new ResourceVector([
    BigInt(4 * bearer.length + 16384) + runtimeBytes, providerBytes, 0n, 8n, 1n, 0n, 0n, 0n, 0n, 0n, 0n,
  ]));
  const active = new Set<AbortController>();
  let closed = false;
  const cleanup = (): void => { if (closed && active.size === 0) { bearer = undefined; dependency.release(); } };
  dependency.onClose(() => { closed = true; for (const controller of active) controller.abort(); cleanup(); });
  const charge = new ResourceVector([BigInt(headerBytes * 4 + 32768) + runtimeBytes, providerBytes, 0n, 16n, 2n, 3n, 1n, 1n, 1n, 0n, 1n]);
  const requestAuthorization: V4LiveAuthorizationProvider = async (request, destination, call) => {
    dependency.check(); call.check(); deadline.check();
    requireControl(!closed && bearer !== undefined && !call.signal.aborted, "closed");
    requireControl(request.authority === authority && request.tenant === tenant && request.audience === audience, "control_request_binding");
    requireControl(byteLength(destination) >= 1 && byteLength(destination) <= 4096, "control_response_capacity");
    requireControl(active.size < maxConcurrentRequests, "resource_exhausted");
    const resources = owner.resources, reservation = resources.root.reserve({ accounts: resources.accounts, owner: { ...resources.owner, kind: "browser_live_https_request" }, charge });
    const controller = new AbortController(); active.add(controller);
    let timer: ReturnType<typeof setTimeout> | undefined, body: Uint8Array | undefined;
    let response: Response | undefined, reader: ReadableStreamDefaultReader<Uint8Array> | undefined, success = false;
    const abort = (): void => controller.abort();
    call.signal.addEventListener("abort", abort, { once: true });
    try {
      const window = new TrustedWindow(owner.clock, timeoutMS);
      const guard = (): void => {
        dependency.check(); reservation.check(); call.check(); deadline.check(); window.check();
        requireControl(!closed && !controller.signal.aborted && !call.signal.aborted, "canceled");
        requireControl(globalThis.location.origin === applicationOrigin && owner.clock.sample().requireInterval().lowerMS >= notBeforeMS, "control_request_binding");
      };
      const tick = (): void => {
        try {
          guard(); const local = window.remainingMS(), absolute = deadline.remainingMS();
          timer = setTimeout(tick, timerChunk(local < absolute ? local : absolute));
        } catch { controller.abort(); }
      };
      body = new Uint8Array(1024); const encoded = encodeLiveAuthorizationRequest(request, body);
      tick(); guard();
      response = await nativeFetch(endpoint, { method: "POST", mode: "cors", credentials: "omit", redirect: "error", cache: "no-store",
        referrerPolicy: "no-referrer", keepalive: false, signal: controller.signal,
        headers: { "Content-Type": "application/cbor", "Accept": "application/cbor", "Cache-Control": "no-store", "Authorization": `Bearer ${bearer}` },
        body: encoded as Uint8Array<ArrayBuffer> });
      guard();
      requireControl(response.status === 200 && !response.redirected && response.url === endpoint && (response.type === "basic" || response.type === "cors"), "control_response_invalid");
      let observedHeaderBytes = 0, headerCount = 0;
      for (const [name, value] of response.headers) {
        observedHeaderBytes += 2 * (name.length + value.length) + 4; headerCount++;
        requireControl(observedHeaderBytes <= headerBytes && headerCount <= 256, "control_response_invalid");
      }
      const length = response.headers.get("content-length");
      requireControl(response.headers.get("content-type") === "application/cbor" && !response.headers.has("content-encoding") &&
        !response.headers.has("transfer-encoding") && !response.headers.has("trailer") && length !== null && /^[1-9][0-9]{0,9}$/u.test(length), "control_response_invalid");
      const size = Number(length); requireControl(size <= byteLength(destination) && response.body !== null, "control_response_invalid");
      reader = response.body.getReader();
      let received = 0;
      while (true) {
        const next = await reader.read(); guard();
        if (next.done) break;
        const count = byteLength(next.value);
        requireControl(count > 0 && count <= size - received, "control_response_invalid");
        copy.call(destination, byteSlice(next.value, 0, count), received); received += count;
      }
      requireControl(received === size, "control_response_invalid"); guard(); success = true; return received;
    } catch { throw new Error(call.signal.aborted || controller.signal.aborted ? "canceled" : "live_authorization_failed"); }
    finally {
      if (timer !== undefined) clearTimeout(timer); call.signal.removeEventListener("abort", abort);
      if (!success) controller.abort();
      // Cancellation is not native completion. Keep request, destination and
      // provider allowances through actual Fetch/read/cancel completion.
      if (reader !== undefined) {
        if (!success) await reader.cancel().catch(() => undefined);
        await reader.closed.catch(() => undefined); reader.releaseLock();
      } else if (response?.body !== undefined && response.body !== null) await response.body.cancel().catch(() => undefined);
      body?.fill(0); if (!success) destination.fill(0);
      reservation.release(); active.delete(controller); cleanup();
    }
  };
  return bindLiveAuthorizationConfig(owner, Object.freeze({ requestAuthorization, maxConcurrentRequests, runtimeBytes, providerBytes }));
}
