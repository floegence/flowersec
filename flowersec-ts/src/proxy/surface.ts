import { bindProxyRequestAssociation, proxyRequestAssociation } from "./requestAssociation.js";
import type { ProxyRuntime, ProxyRuntimeOptions, ProxySurfaceMode, ProxySessionBinding, ProxySurfaceRequestPolicy, ProxyClearResult } from "./types.js";
import type { ProxyStream } from "./stream.js";
import type { V4CleanupStatus } from "../generated/transportV4APIResults.js";
import { createProxyRuntime, ensureServiceWorkerRuntimeRegistered } from "./runtime.js";
import { normalizePath } from "./policy.js";
import { registerProxyControllerWindow, type ProxyControllerWindowHandle } from "./windowBridge.js";
import { registerServiceWorkerAndEnsureControl, type RegisterServiceWorkerOptions } from "./registerServiceWorker.js";
import { registerProxyRuntimeServiceWorkerBridge, usesServiceWorkerResponseFlowControl, enableResponseFlowControl } from "./serviceWorkerRuntime.js";
import { nextServiceWorkerPublicationOwnerEpoch, serviceWorkerPublicationOwner } from "./publicationOwner.js";
import { PROXY_CREDENTIAL_CONTROL_PATH, proxyCredentialControl, type ProxyCredentialAction } from "./credentialControl.js";
import { PROXY_WIRE_VERSION } from "./wire.js";
import { type OperationOptions } from "../public/contract.js";
export { PROXY_CREDENTIAL_CONTROL_PATH } from "./credentialControl.js";

export interface ProxySurfaceOptions {
  readonly mode: ProxySurfaceMode;
  readonly binding: ProxySessionBinding;
  readonly hostOrigin: string;
  readonly contentOrigin: string;
  readonly requestPolicy: ProxySurfaceRequestPolicy;
  readonly runtime?: Omit<ProxyRuntimeOptions, "session" | "sessionBinding" | "credentialContext" | "registerServiceWorkerBridge">;
  readonly serviceWorker?: RegisterServiceWorkerOptions;
  readonly contentWindow?: Window;
  readonly hostWindow?: Window;
  /** Fixed host-owned upper bound for an isolated window attachment. */
  readonly attachmentLifetimeMS?: number;
  /** Host-observed navigation/document lifecycle revokes the attachment. */
  readonly attachmentLifecycleSignal?: AbortSignal;
  /** Authorization and scope are resolved by trusted server configuration. */
  readonly credentials?: Readonly<{ mode: "upstream_cookie_session"; context: "delegated_first_party" }>;
}
export interface ProxySurface {
  readonly mode: ProxySurfaceMode;
  readonly generation: string;
  readonly runtime: ProxyRuntime;
  readonly publicationOwners: readonly string[];
  /** Only the content attachment capability is disclosed; no Session or source. */
  readonly contentBootstrap?: Readonly<{ controllerOrigin: string; capabilityNonce: string }>;
  clearUpstreamCredentials(options?: Readonly<{ reuseAfterClear?: boolean; timeoutMS?: number }> & OperationOptions): Promise<ProxyClearResult>;
  cleanupStatus(): V4CleanupStatus;
  dispose(): Promise<void>;
}
function origin(value: string): string {
  const url = new URL(value);
  if (url.origin !== value || !["https:", "http:"].includes(url.protocol)) throw new TypeError("invalid surface origin");
  return value;
}
type ClearObservation = {
  serverInvalidation: ProxyClearResult["serverInvalidation"];
  ownedDeliveryFence: ProxyClearResult["ownedDeliveryFence"];
  associationInstallation: ProxyClearResult["associationInstallation"];
};
function nonce(length = 16): string {
  const bytes = new Uint8Array(length); globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}
function observeClear(actual: Promise<ProxyClearResult>, wait: OperationOptions & Readonly<{ timeoutMS?: number }>,
  snapshot: (callError: ProxyClearResult["callError"]) => ProxyClearResult): Promise<ProxyClearResult> {
  const timeout = wait.timeoutMS ?? 10000;
  if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 60000) throw new TypeError("invalid Clear deadline");
  const deadline = AbortSignal.timeout(timeout);
  const signal = wait.signal === undefined ? deadline : AbortSignal.any([wait.signal, deadline]);
  return new Promise<ProxyClearResult>((resolve, reject) => {
    let settled = false;
    const finish = (work: () => void): void => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      work();
    };
    const onAbort = (): void => finish(() => resolve(snapshot(
      deadline.aborted && !wait.signal?.aborted ? "deadline_exceeded" : "canceled")));
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) { onAbort(); return; }
    void actual.then(value => finish(() => resolve(value)), error => finish(() => reject(error)));
  });
}
/** A single composition owns attachment, credentials, and every actual trusted
 * publication boundary. An isolated content crossing is already disclosure. */
export async function createProxySurface(options: ProxySurfaceOptions): Promise<ProxySurface> {
  const hostOrigin = origin(options.hostOrigin), contentOrigin = origin(options.contentOrigin);
  if (options.mode !== "trusted" && options.mode !== "isolated" || options.mode === "trusted" && hostOrigin !== contentOrigin ||
      options.mode === "isolated" && (hostOrigin === contentOrigin || options.contentWindow === undefined || options.serviceWorker !== undefined)) throw new TypeError("invalid surface trust boundary");
  const methods = new Set(options.requestPolicy.methods);
  if (methods.size === 0 || [...methods].some(method => !/^[A-Z]+$/u.test(method))) throw new TypeError("invalid surface method policy");
  if (options.mode === "isolated" && (options.requestPolicy.paths.allowedPathPrefixes?.length ?? 0) === 0) throw new TypeError("isolated surface requires an explicit path scope");
  const generation = nonce(), capability = nonce(32), stops = new Set<() => void>(), tails = new Set<Promise<unknown>>();
  let context: string | undefined, epoch = 0, disposed = false, fenced = true, contextPublished = false, attachmentRevoked = false;
  let disposal: Promise<void> | undefined, attachment: ProxyControllerWindowHandle | undefined;
  let bridge: Readonly<{ dispose(): void }> | undefined, raw: ProxyRuntime | undefined;
  let swOwner: ReturnType<typeof serviceWorkerPublicationOwner> | undefined;
  let operation: { old: string; reuse: boolean; promise: Promise<ProxyClearResult>; observation: ClearObservation } | undefined;
  const tail = (work: Promise<unknown>): void => { tails.add(work); void work.then(() => tails.delete(work), () => tails.delete(work)); };
  const cleanupStatus = (): V4CleanupStatus => {
    const local = raw?.cleanupStatus?.(), remote = swOwner?.cleanupStatus();
    const pending = BigInt(tails.size) + (local?.pending_callbacks ?? 0n) + (remote?.pending_callbacks ?? 0n);
    const complete = pending === 0n && local?.core_cleanup !== "pending" && remote?.core_cleanup !== "pending";
    return Object.freeze({ status: complete ? "complete" : "pending", core_cleanup: complete ? "complete" : "pending", pending_callbacks: pending });
  };
  const gate = (captured: number): void => { if (disposed || fenced || epoch !== captured) throw new Error("surface_publication_fenced"); };
  const policy = (method: string, path: string): void => {
    if (!methods.has(method) || normalizePath(path).split("?", 1)[0] === PROXY_CREDENTIAL_CONTROL_PATH) throw new Error("surface_request_denied");
  };
  const sealHost = (): void => { fenced = true; contextPublished = false; epoch++; for (const stop of [...stops]) { try { stop(); } catch { /* Each original owner must still be sealed. */ } } };
  const revokeAttachmentOwner = (): void => { attachmentRevoked = true; sealHost(); };
  if (options.mode === "isolated" && options.attachmentLifecycleSignal?.aborted === true) throw new Error("attachment_lifecycle_closed");
  if (options.contentWindow === undefined) options.attachmentLifecycleSignal?.addEventListener("abort", revokeAttachmentOwner, { once: true });
  const control = (action: ProxyCredentialAction, signal?: AbortSignal, capturedContext = context) => proxyCredentialControl(raw!, {
    v: PROXY_WIRE_VERSION, operation_id: nonce(), action, surface_owner: generation,
    ...(action === 1 ? { content_origin: contentOrigin } : { credential_context: capturedContext! }),
  }, signal);
  const result = (serverInvalidation: ProxyClearResult["serverInvalidation"], delivery: ProxyClearResult["ownedDeliveryFence"],
    installation: ProxyClearResult["associationInstallation"], callError?: ProxyClearResult["callError"]): ProxyClearResult => Object.freeze({
    serverInvalidation, ownedDeliveryFence: delivery, associationInstallation: installation,
    clearedForThisSurface: serverInvalidation === "confirmed" && delivery === "confirmed",
    readyForReuse: serverInvalidation === "confirmed" && delivery === "confirmed" && installation === "installed",
    cleanupStatus: cleanupStatus(), deliveryScope: "current_surface_composition", ...(callError === undefined ? {} : { callError }),
  });
  async function dispose(): Promise<void> {
    if (disposal !== undefined) return disposal;
    disposed = true; sealHost();
    if (options.contentWindow === undefined) options.attachmentLifecycleSignal?.removeEventListener("abort", revokeAttachmentOwner);
    attachment?.dispose(); bridge?.dispose();
    disposal = (async () => {
      try {
        await operation?.promise.catch(() => undefined);
        if (context !== undefined && raw !== undefined) await control(3, AbortSignal.timeout(5000));
      }
      finally { swOwner?.close(); raw?.dispose(); }
    })(); tail(disposal); return disposal;
  }
  try {
    if (options.serviceWorker !== undefined) {
      if (options.mode !== "trusted" || options.runtime?.runtimeRegistrationToken === undefined) throw new TypeError("trusted SW requires an explicit runtime registration token");
      await registerServiceWorkerAndEnsureControl(options.serviceWorker);
      const ownerID = `${generation}:service_worker`, ownerEpoch = nextServiceWorkerPublicationOwnerEpoch();
      const ownerClaim = await ensureServiceWorkerRuntimeRegistered({ runtimeRegistrationToken: options.runtime.runtimeRegistrationToken,
        timeoutMs: 10000, publicationOwnerID: ownerID, publicationOwnerEpoch: ownerEpoch });
      if (ownerClaim === undefined) throw new Error("publication_owner_unavailable");
      swOwner = serviceWorkerPublicationOwner(navigator.serviceWorker, options.runtime.runtimeRegistrationToken, ownerID, ownerEpoch, ownerClaim);
    }
    // Validate the initial Session before publishing the Surface. Keep the
    // caller's binding explicit: capture_current must re-run the Controller's
    // authenticated capture gate for every new OPEN so a replacement Session
    // can be used only under the same Controller authorization.
    const initial = options.binding.mode === "fixed" ? options.binding.session : options.binding.controller.captureSession();
    raw = createProxyRuntime({ ...options.runtime, session: initial, sessionBinding: options.binding,
      registerServiceWorkerBridge: false, pathPolicy: options.requestPolicy.paths, externalOrigin: contentOrigin, credentialContext: () => context });
    if (options.credentials !== undefined) {
      if (options.credentials.mode !== "upstream_cookie_session" || options.credentials.context !== "delegated_first_party") throw new TypeError("invalid credential mode");
      const ack = await control(1, AbortSignal.timeout(10000));
      if (!ack.ok || ack.credential_context === undefined) throw new Error("credential_bind_failed"); context = ack.credential_context;
    }
    await swOwner?.install(context ?? "", AbortSignal.timeout(10000));
    if (options.attachmentLifecycleSignal?.aborted === true) throw new Error("attachment_lifecycle_closed");
    fenced = false; contextPublished = true;
    const runtime: ProxyRuntime = Object.freeze({
      limits: raw.limits, cleanupStatus,
      async fetch(input, init) {
        const captured = epoch; gate(captured);
        if (stops.size >= 128) throw new Error("surface_capacity_unavailable");
        const target = input instanceof Request ? input.url : String(input), url = new URL(target, contentOrigin);
        if (url.origin !== contentOrigin) throw new Error("surface_request_denied");
        policy((init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase(), url.pathname + url.search);
        const admission = new AbortController(), stopAdmission = () => admission.abort(); stops.add(stopAdmission);
        const requestSignal = init?.signal ?? (input instanceof Request ? input.signal : undefined);
        let response: Response;
        try { response = await raw!.fetch(input, { ...init, signal: requestSignal === undefined ? admission.signal : AbortSignal.any([requestSignal, admission.signal]) }); }
        finally { stops.delete(stopAdmission); }
        try { gate(captured); } catch (error) { tail(response.body?.cancel() ?? Promise.resolve()); throw error; }
        if (response.body === null) return response;
        const reader = response.body.getReader(); let controller: ReadableStreamDefaultController<Uint8Array> | undefined, closed = false;
        const release = (): void => { stops.delete(stop); try { reader.releaseLock(); } catch { /* already released */ } };
        const stop = (): void => { if (closed) return; closed = true; controller?.error(new Error("surface_publication_fenced")); const work = reader.cancel().then(release, release); tail(work); };
        stops.add(stop);
        const body = new ReadableStream<Uint8Array>({ start(value) { controller = value; },
          async pull(output) {
            try { gate(captured); const read = reader.read(); tail(read); const next = await read; gate(captured);
              if (next.done) { closed = true; output.close(); release(); } else output.enqueue(next.value);
            } catch (error) { if (!closed) { closed = true; output.error(error); } await reader.cancel().catch(() => undefined); release(); }
          }, async cancel(reason) { closed = true; await reader.cancel(reason).catch(() => undefined); release(); },
        });
        return new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers });
      },
      dispatchFetch(request, port) {
        const captured = epoch; gate(captured); policy(request.method, request.path);
        if (stops.size >= 128) throw new Error("surface_capacity_unavailable");
        const association = proxyRequestAssociation(request);
        if (association !== undefined && association.context !== context) throw new Error("surface_publication_fenced");
        const cancellation = new AbortController();
        const bound = Object.freeze({ ...request, requestOrigin: association?.requestOrigin ?? contentOrigin });
        bindProxyRequestAssociation(bound, { context: association?.context ?? context, ...(association?.generation === undefined ? {} : { generation: association.generation }), requestOrigin: association?.requestOrigin ?? contentOrigin, signal: cancellation.signal });
        if (usesServiceWorkerResponseFlowControl(request)) enableResponseFlowControl(bound);
        const stop = (): void => { stops.delete(stop); cancellation.abort(); try { port.postMessage({ type: "flowersec-proxy:response_error", status: 503, code: "closed", message: "surface publication fenced" }); } finally { port.close(); } };
        stops.add(stop);
        const guarded = new Proxy(port, { get(target, name) {
          if (name === "postMessage") return (...args: unknown[]) => { gate(captured); return Reflect.apply(target.postMessage, target, args); };
          if (name === "close") return () => { stops.delete(stop); target.close(); };
          const value = Reflect.get(target, name, target); return typeof value === "function" ? value.bind(target) : value;
        }, set(target, name, value) { return Reflect.set(target, name, value, target); } });
        try { raw!.dispatchFetch(bound, guarded); } catch (error) { stops.delete(stop); throw error; }
      },
      async openWebSocketStream(path, wait) {
        const captured = epoch; gate(captured);
        if (!options.requestPolicy.allowWebSocket || normalizePath(path).split("?", 1)[0] === PROXY_CREDENTIAL_CONTROL_PATH) throw new Error("surface_request_denied");
        if (stops.size >= 128) throw new Error("surface_capacity_unavailable");
        const admission = new AbortController(), stopAdmission = () => admission.abort(); stops.add(stopAdmission);
        let opened: Awaited<ReturnType<ProxyRuntime["openWebSocketStream"]>>;
        try { opened = await raw!.openWebSocketStream(path, { ...wait, signal: wait?.signal === undefined ? admission.signal : AbortSignal.any([wait.signal, admission.signal]) }); }
        finally { stops.delete(stopAdmission); }
        try { gate(captured); } catch (error) { tail(opened.stream.reset()); throw error; }
        const original = opened.stream;
        const stop = (): void => { stops.delete(stop); tail(original.reset()); };
        stops.add(stop);
        const stream: ProxyStream = Object.freeze<ProxyStream>({ ...(original.signal === undefined ? {} : { signal: original.signal }),
          async read(options) { gate(captured); const value = await original.read(options); gate(captured); return value; },
          async write(bytes, options) { gate(captured); return await original.write(bytes, options); },
          async closeWrite(options) { gate(captured); await original.closeWrite(options); },
          ...(original.finish === undefined ? {} : { finish: async (options?: OperationOptions) => { gate(captured); await original.finish!(options); stops.delete(stop); } }),
          async reset() { stops.delete(stop); await original.reset(); }, async close() { stops.delete(stop); await original.close(); },
          dispose(onCleanup) { stops.delete(stop); original.dispose?.(onCleanup); },
        }); return Object.freeze({ stream, protocol: opened.protocol });
      }, dispose() { void dispose().catch(() => undefined); },
    });
    if (options.serviceWorker !== undefined) bridge = registerProxyRuntimeServiceWorkerBridge(runtime, navigator.serviceWorker);
    if (options.contentWindow !== undefined) attachment = registerProxyControllerWindow({ runtime, allowedOrigins: [contentOrigin],
      expectedSource: options.contentWindow, capabilityNonce: capability,
      ...(options.attachmentLifetimeMS === undefined ? {} : { attachmentLifetimeMS: options.attachmentLifetimeMS }),
      ...(options.attachmentLifecycleSignal === undefined ? {} : { lifecycleSignal: options.attachmentLifecycleSignal }),
      onRevoke: revokeAttachmentOwner,
      ...(options.hostWindow === undefined ? {} : { targetWindow: options.hostWindow }) });
    return Object.freeze<ProxySurface>({ mode: options.mode, generation, runtime, cleanupStatus, dispose,
      publicationOwners: Object.freeze([`${generation}:host`, ...(swOwner === undefined ? [] : [swOwner.ownerID])]),
      ...(options.contentWindow === undefined ? {} : { contentBootstrap: Object.freeze({ controllerOrigin: hostOrigin, capabilityNonce: capability }) }),
      clearUpstreamCredentials(wait = {}) {
        const reuse = wait.reuseAfterClear ?? true;
        if (typeof reuse !== "boolean") throw new TypeError("invalid Clear intent");
        const joined = operation;
        if (joined !== undefined && (!contextPublished || joined.old === context)) {
          return joined.reuse === reuse ? observeClear(joined.promise, wait, callError => result(
            joined.observation.serverInvalidation, joined.observation.ownedDeliveryFence,
            joined.observation.associationInstallation, callError)) : Promise.resolve(result("not_attempted", "unconfirmed", "not_installed", "operation_conflict"));
        }
        if (disposed || context === undefined) return Promise.resolve(result("not_attempted", "unconfirmed", "not_installed", "source_unavailable"));
        const timeout = wait.timeoutMS ?? 10000;
        if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 60000) throw new TypeError("invalid Clear deadline");
        const old = context; sealHost(); const captured = epoch;
        const deadline = AbortSignal.timeout(timeout), signal = wait.signal === undefined ? deadline : AbortSignal.any([wait.signal, deadline]);
        const observation: ClearObservation = { serverInvalidation: "not_attempted",
          ownedDeliveryFence: swOwner === undefined ? "confirmed" : "unconfirmed", associationInstallation: "not_installed" };
        const promise = (async (): Promise<ProxyClearResult> => {
          let failure: ProxyClearResult["callError"] | undefined;
          let installationAttempted = false;
          const fence = swOwner === undefined ? Promise.resolve() : swOwner.fence(old, signal).then(() => {
            observation.ownedDeliveryFence = "confirmed";
          });
          tail(fence); void fence.catch(() => undefined);
          try {
            signal.throwIfAborted(); observation.serverInvalidation = "unknown";
            const ack = await control(2, signal, old);
            if (ack.server_invalidated === true) observation.serverInvalidation = "confirmed";
            if (ack.credential_context !== undefined) context = ack.credential_context; // Reserved candidate survives false intent and installation failure.
            await fence; signal.throwIfAborted();
            if (!ack.ok) failure = "association_install_failed";
            if (reuse && ack.ok && ack.credential_context !== undefined && observation.serverInvalidation === "confirmed" && observation.ownedDeliveryFence === "confirmed") {
              if (attachmentRevoked) { failure = "source_unavailable"; }
              else {
                try {
                  installationAttempted = swOwner !== undefined;
                  await swOwner?.install(context!, signal);
                  signal.throwIfAborted();
                  if (!disposed && !attachmentRevoked && captured === epoch) {
                    fenced = false; contextPublished = true; observation.associationInstallation = "installed";
                  }
                } catch { failure = signal.aborted ? deadline.aborted ? "deadline_exceeded" : "canceled" : "association_install_failed"; }
              }
            }
          } catch { failure = signal.aborted ? deadline.aborted ? "deadline_exceeded" : "canceled" : "credential_clear_failed"; }
          if (installationAttempted && observation.associationInstallation !== "installed" && context !== undefined && swOwner !== undefined) {
            const refence = swOwner.fence(context, AbortSignal.timeout(5000)); tail(refence);
            await refence.catch(() => undefined);
          }
          return result(observation.serverInvalidation, observation.ownedDeliveryFence, observation.associationInstallation, failure);
        })(); operation = { old, reuse, promise, observation }; return promise;
      },
    });
  } catch (error) { await dispose().catch(() => undefined); throw error; }
}
