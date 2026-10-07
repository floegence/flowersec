import type { V4TransportEnvironment } from "../v4/public.js";
import { originalEnvironment } from "../v4/runtime/environment.js";
import { ResourceVector } from "../v4/runtime/resources.js";
import { TrustedDeadline, TrustedWindow, timerChunk } from "../v4/runtime/deadline.js";
import { equalCredential, requireCredential } from "../v4/runtime/credentialSupport.js";
import { capturePoolServerAllowConfiguration, clearPoolServerAllowConfiguration, poolServerAllowConfigurationCharge, encodeTunnelServerAllow, type PoolServerAllowPublication, type PoolServerAllowConfiguration, type PoolServerAllowRecipient } from "../v4/runtime/poolServerAllow.js";
import type { V4BrowserLiveHTTPSDeployment } from "./liveHTTPSV4.js";

const nativeFetch = globalThis.fetch;
export interface BrowserPoolServerAllowOptions {
  readonly deployment: V4BrowserLiveHTTPSDeployment;
  readonly tenant: string; readonly audience: string;
  readonly bearerToken: string; readonly credentialNotAfterMS: bigint;
  readonly timeoutMS: bigint; readonly headerBytes: number;
  readonly runtimeBytes: bigint; readonly providerBytes: bigint;
}
/** The installed terminator authenticates this credential and forwards the
 * original Allow to the fixed B recipient over its authenticated control link.
 * Fetch requires the same TLS 1.3/no-early-data deployment evidence as live
 * authorization, including exposed identity-encoded response framing. */
export function createBrowserPoolServerAllow(environment: V4TransportEnvironment, options: BrowserPoolServerAllowOptions,
  recipients: readonly PoolServerAllowRecipient[]): PoolServerAllowConfiguration & { close(): Promise<void> } {
  const runtime = originalEnvironment(environment), deployment = Object.freeze({ ...options.deployment });
  const { tenant, audience, credentialNotAfterMS, timeoutMS, headerBytes, runtimeBytes, providerBytes } = options;
  let bearer: string | undefined = options.bearerToken;
  const identifier = /^[a-z0-9][a-z0-9._:/@-]{0,127}$/u;
  requireCredential(typeof nativeFetch === "function" && globalThis.isSecureContext && typeof globalThis.location?.origin === "string" &&
    typeof deployment.baseURL === "string" && deployment.baseURL.length <= 2048 && !/[\s%\\?#]/u.test(deployment.baseURL) &&
    typeof deployment.deploymentID === "string" && identifier.test(deployment.deploymentID) && typeof deployment.revision === "string" && identifier.test(deployment.revision) && deployment.terminatorProfile === "tls13-no-early-data-authenticated-control" &&
    typeof deployment.evidenceReference === "string" && deployment.evidenceReference.length > 0 && deployment.evidenceReference.length <= 1024 &&
    typeof tenant === "string" && identifier.test(tenant) && typeof audience === "string" && identifier.test(audience) && typeof bearer === "string" && bearer.length > 0 && bearer.length <= 8192 && /^[A-Za-z0-9._~+/-]+=*$/u.test(bearer) &&
    typeof deployment.notBeforeMS === "bigint" && deployment.notBeforeMS >= 0n && typeof deployment.notAfterMS === "bigint" && deployment.notAfterMS > deployment.notBeforeMS && deployment.notAfterMS <= 0xffffffffffffffffn &&
    typeof credentialNotAfterMS === "bigint" && credentialNotAfterMS > deployment.notBeforeMS && credentialNotAfterMS <= 0xffffffffffffffffn &&
    typeof timeoutMS === "bigint" && timeoutMS > runtime.clock.profile.rate.elapsed(0n).upperMS && timeoutMS <= 2000n && Number.isSafeInteger(headerBytes) && headerBytes >= 1024 && headerBytes <= 65536 &&
    typeof runtimeBytes === "bigint" && runtimeBytes > 0n && typeof providerBytes === "bigint" && providerBytes >= 262144n + BigInt(4 * headerBytes), "configuration_capacity");
  const base = new URL(deployment.baseURL), origin = new URL(deployment.applicationOrigin);
  requireCredential(base.protocol === "https:" && base.username === "" && base.password === "" && base.search === "" && base.hash === "" &&
    deployment.baseURL.replace(/\/$/u, "") === base.href.replace(/\/$/u, "") && origin.protocol === "https:" && origin.origin === deployment.applicationOrigin &&
    deployment.applicationOrigin === globalThis.location.origin, "configuration_capacity");
  const deadline = new TrustedDeadline(runtime.clock, deployment.notAfterMS < credentialNotAfterMS ? deployment.notAfterMS : credentialNotAfterMS);
  deadline.check(); requireCredential(runtime.clock.sample().requireInterval().lowerMS >= deployment.notBeforeMS, "credential_expired");
  const endpoint = base.origin + base.pathname.replace(/\/$/u, "") + "/tunnel/server-allow", input: PoolServerAllowConfiguration = { recipients, prepare: () => { throw new Error("owner_unavailable"); } };
  // This bounded adapter admits one publication slot during installation,
  // before any Connect can consume its lease or enter Fetch.
  const dependency = runtime.admitDependency("browser_pool_server_allow", new ResourceVector([BigInt(4 * bearer.length + 4 * headerBytes + 262144) + runtimeBytes, providerBytes, 0n, 32n, 2n, 3n, 1n, 1n, 1n, 0n, 1n]).add(poolServerAllowConfigurationCharge(input)));
  let captured: PoolServerAllowConfiguration | undefined, closed = false, active: AbortController | undefined, pending: Promise<void> | undefined, closing: Promise<void> | undefined;
  let reserved = false, slotDone: Promise<void> | undefined, releaseSlot: (() => void) | undefined;
  const close = (): Promise<void> => { closed = true; active?.abort(); releaseSlot?.(); return closing ??= (async () => { await slotDone; await pending; bearer = undefined; clearPoolServerAllowConfiguration(captured); dependency.release(); })(); };
  try {
    captured = capturePoolServerAllowConfiguration(input); dependency.onClose(() => { void close(); });
    const prepare: PoolServerAllowConfiguration["prepare"] = (request, grant) => {
      dependency.check(); deadline.check(); requireCredential(!closed && !reserved && active === undefined && bearer !== undefined && request.tenant === tenant && request.audience === audience, "credential_binding");
      const original = captured!.recipients.find(value => value.candidateIndex === request.candidateIndex);
      requireCredential(original !== undefined && equalCredential(original.recipient, request.recipient) && equalCredential(original.incarnation, request.incarnation) && equalCredential(original.grant, grant), "credential_binding");
      const backing = new Uint8Array(66560); let body: Uint8Array;
      try { body = encodeTunnelServerAllow(request, grant, backing); } catch (error) { backing.fill(0); throw error; }
      reserved = true; let entered = false, released = false, physical = false, resolveSlot!: () => void; slotDone = new Promise(resolve => { resolveSlot = resolve; });
      const release = (): void => { if (released || physical) return; released = true; backing.fill(0); reserved = false; releaseSlot = undefined; slotDone = undefined; resolveSlot(); };
      releaseSlot = release;
      return Object.freeze({ close: release, publish: async (call: Parameters<PoolServerAllowPublication["publish"]>[0]): Promise<void> => {
      dependency.check(); call.check(); deadline.check(); requireCredential(!closed && !entered && !released && !call.signal.aborted, "credential_closed"); entered = true; physical = true;
      const controller = new AbortController(); active = controller; let resolve!: () => void; pending = new Promise(done => { resolve = done; });
      let timer: ReturnType<typeof setTimeout> | undefined, response: Response | undefined, reader: ReadableStreamDefaultReader<Uint8Array> | undefined, complete = false;
      const stop = (): void => { controller.abort(); }; call.signal.addEventListener("abort", stop, { once: true });
      try {
        const window = new TrustedWindow(runtime.clock, timeoutMS), check = (): void => {
          dependency.check(); call.check(); deadline.check(); window.check(); requireCredential(!closed && !controller.signal.aborted && !call.signal.aborted &&
            globalThis.location.origin === deployment.applicationOrigin && runtime.clock.sample().requireInterval().lowerMS >= deployment.notBeforeMS, "credential_closed");
        };
        const tick = (): void => { try { check(); const limits = [window.remainingMS(), deadline.remainingMS(), call.remainingMS()]; timer = setTimeout(tick, timerChunk(limits.reduce((a, b) => a < b ? a : b))); } catch { stop(); } };
        tick(); check();
        response = await nativeFetch(endpoint, { method: "POST", mode: "cors", credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer", keepalive: false, signal: controller.signal,
          headers: { "Content-Type": "application/cbor", "Accept": "application/cbor", "Cache-Control": "no-store", "Authorization": `Bearer ${bearer}` }, body: body as Uint8Array<ArrayBuffer> }); check();
        requireCredential(response.status === 200 && !response.redirected && response.url === endpoint && (response.type === "basic" || response.type === "cors"), "credential_binding");
        let bytes = 0, count = 0; for (const [name, value] of response.headers) { bytes += 2 * (name.length + value.length) + 4; count++; requireCredential(bytes <= headerBytes && count <= 256, "configuration_capacity"); }
        requireCredential(response.headers.get("content-type") === "application/cbor" && response.headers.get("content-length") === "1" &&
          !response.headers.has("content-encoding") && !response.headers.has("transfer-encoding") && !response.headers.has("trailer") && response.body !== null, "credential_binding");
        reader = response.body.getReader(); let received = 0;
        for (;;) { const next = await reader.read(); check(); if (next.done) break;
          requireCredential(next.value.length <= 1 - received && (next.value.length === 0 || next.value[0] === 0xf5), "credential_binding"); received += next.value.length; }
        check(); requireCredential(received === 1, "credential_binding"); complete = true;
      } finally {
        if (timer !== undefined) clearTimeout(timer); call.signal.removeEventListener("abort", stop); if (!complete) controller.abort();
        if (reader !== undefined) { if (!complete) await reader.cancel().catch(() => undefined); await reader.closed.catch(() => undefined); reader.releaseLock(); }
        else if (response?.body !== undefined && response.body !== null) await response.body.cancel().catch(() => undefined);
        active = undefined; pending = undefined; physical = false; release(); resolve();
      }
      } });
    };
    return Object.freeze({ recipients: captured.recipients, prepare, close });
  } catch (error) { clearPoolServerAllowConfiguration(captured); dependency.release(); throw error; }
}
