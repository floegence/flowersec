import * as sdk from "../browser/index.js";
import { originalEnvironment } from "../v4/runtime/environment.js";
import { equalCredential } from "../v4/runtime/credentialSupport.js";
import { encodeTunnelServerAllow, capturePoolServerAllowConfiguration, clearPoolServerAllowConfiguration, poolServerAllowConfigurationCharge } from "../v4/runtime/poolServerAllow.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";

/** Host-provisioned application installation, separate from acquisition.
 * Every declaration comes from the original deployment file. This module does
 * not discover trust, capabilities, or a clock from an acquired credential. */
export interface BrowserRunnerInstallation {
  pool_server_allow?: Readonly<{ endpoint: "/runner/server-allow"; recipient: string; incarnation: string }>;
  material_sha256: string; identity_seed: string; dh_seed: string;
  application_origin: string; spend_authority: string; issuer_key_id: string;
  database_name: string; store_id: string; store_generation: string;
  host_capability: string; host_endpoint: string; bootstrap_endpoint: string;
  policy: Parameters<sdk.BrowserWSSClient["registerPoolSource"]>[0];
  namespaces: readonly { tenant: string; authority: string; generation: number; root_key_id: string; root_public_key: string }[];
  carrier: "wss" | "webtransport";
  deployment: Record<string, unknown> & { routeDigest: string; notBeforeMS: string; notAfterMS: string; applicationOrigin: string; endpoint: string };
  limits: Record<string, number | string>;
  resource_limit: readonly string[]; tenant_id: string; profile_revision: string;
  service_namespace: string; service_query_type: number; service_query_digest: string; service_schema_digest: string;
  application_schema?: "echo" | "parity";
  service_notification_contract?: string;
  service_contracts?: readonly Readonly<{ type_id: number; contract: string }>[];
  server_identity_digest: string; max_message_bytes: number; max_streams: number;
  carrier_runtime_bytes: string; provider_runtime_bytes: string; provider_stream_bytes: string;
  carrier_application_streams?: number;
}
const base64 = (bytes: Uint8Array) => { let result = ""; for (let i = 0; i < bytes.length; i += 8192) result += String.fromCharCode(...bytes.subarray(i, i + 8192)); return btoa(result); };
function bytes(value: string, bound: number): Uint8Array<ArrayBuffer> {
  if (typeof value !== "string" || value.length > Math.ceil(bound / 3) * 4) throw new Error("installation byte bound");
  const result = Uint8Array.from(atob(value), c => c.charCodeAt(0));
  if (result.length === 0 || result.length > bound || base64(result) !== value) throw new Error("noncanonical installation bytes"); return result;
}
const hex = (input: Uint8Array) => Array.from(input, value => value.toString(16).padStart(2, "0")).join("");
const originalFetch = globalThis.fetch;
function runnerServerAllow(environment: sdk.TransportEnvironment, config: BrowserRunnerInstallation,
  tunnels: readonly { role: number; candidate_index: number; grant: string }[]): sdk.PoolServerAllowConfiguration | undefined {
  if (tunnels.length === 0) { if (config.pool_server_allow !== undefined) throw new Error("direct Allow installation"); return undefined; }
  const installed = config.pool_server_allow, origin = config.application_origin, capability = config.host_capability, endpoint = installed?.endpoint;
  if (installed === undefined || endpoint !== "/runner/server-allow" || location.origin !== origin || !/^[0-9a-f]{64}$/u.test(capability)) throw new Error("original pool Allow host installation missing");
  const owned: Uint8Array[] = [], copy = (value: string, cap: number): Uint8Array => { const result = bytes(value, cap); owned.push(result); return result; };
  let declaration: sdk.PoolServerAllowConfiguration;
  try {
    declaration = { recipients: tunnels.filter(value => value.role === 1).map(value => ({ candidateIndex: value.candidate_index, grant: copy(value.grant, 65536), recipient: copy(installed.recipient, 16), incarnation: copy(installed.incarnation, 16) })), prepare: () => { throw new Error("original preparation required"); } };
    const owner = originalEnvironment(environment), dependency = owner.admitDependency("browser_host_pool_allow", new sdk.ResourceVector([1048576n + owner.resources.runtimeBytes, 4194304n, 0n, 32n, 2n, 3n, 1n, 1n, 1n, 0n, 1n]).add(poolServerAllowConfigurationCharge(declaration)));
    let captured: sdk.PoolServerAllowConfiguration | undefined, closed = false, reserved = false, active: AbortController | undefined, releaseSlot: (() => void) | undefined;
    const cleanup = (): void => { if (closed && !reserved) { clearPoolServerAllowConfiguration(captured); dependency.release(); } };
    try {
      captured = capturePoolServerAllowConfiguration(declaration); dependency.onClose(() => { closed = true; active?.abort(); releaseSlot?.(); cleanup(); });
      const result = Object.freeze({ recipients: captured.recipients, prepare: (request: sdk.TunnelServerAllowRequest, grant: Uint8Array): sdk.PoolServerAllowPublication => {
        dependency.check(); if (closed || reserved || location.origin !== origin) throw new Error("original Allow slot unavailable");
        const recipient = captured!.recipients.find(value => value.candidateIndex === request.candidateIndex);
        if (recipient === undefined || !equalCredential(recipient.recipient, request.recipient) || !equalCredential(recipient.incarnation, request.incarnation) ||
          !equalCredential(recipient.grant, grant)) throw new Error("original Allow binding differs");
        const backing = new Uint8Array(66560); let body: Uint8Array | undefined;
        try { body = new TextEncoder().encode(JSON.stringify({ capability, wire: base64(encodeTunnelServerAllow(request, grant, backing)) })); }
        finally { backing.fill(0); }
        const originalBody = body; reserved = true; let entered = false, physical = false, released = false;
        const release = (): void => { if (physical || released) return; released = true; originalBody.fill(0); reserved = false; releaseSlot = undefined; cleanup(); };
        releaseSlot = release;
        return Object.freeze({ close: release, publish: async (call: Parameters<sdk.PoolServerAllowPublication["publish"]>[0]) => {
          dependency.check(); call.check(); if (closed || entered || released || location.origin !== origin) throw new Error("original Allow unavailable"); entered = true; physical = true;
          const abort = new AbortController(); active = abort; const stop = (): void => { abort.abort(); }; call.signal.addEventListener("abort", stop, { once: true });
          let timer: ReturnType<typeof setTimeout> | undefined, response: Response | undefined, reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
          try {
            const check = (): void => { dependency.check(); call.check(); if (closed || abort.signal.aborted || call.signal.aborted || location.origin !== origin) throw new Error("original Allow canceled"); };
            check(); timer = setTimeout(stop, Number(call.remainingMS())); check();
            response = await originalFetch(endpoint, { method: "POST", credentials: "omit", redirect: "error", cache: "no-store", keepalive: false, signal: abort.signal,
              headers: { "content-type": "application/json" }, body: originalBody as Uint8Array<ArrayBuffer> }); check();
            if (response.status !== 200 || response.redirected || response.url !== new URL(endpoint, origin).href || response.headers.get("content-type") !== "application/cbor" ||
              response.headers.get("content-length") !== "1" || response.body === null) throw new Error("original Allow rejected");
            reader = response.body.getReader(); let received = 0;
            for (;;) { const next = await reader.read(); check(); if (next.done) break; if (next.value.length > 1 - received || next.value.length !== 0 && next.value[0] !== 0xf5) throw new Error("invalid Allow response"); received += next.value.length; }
            if (received !== 1) throw new Error("invalid Allow response"); check();
          } finally {
            if (timer !== undefined) clearTimeout(timer); call.signal.removeEventListener("abort", stop); abort.abort();
            if (reader !== undefined) { await reader.cancel().catch(() => undefined); await reader.closed.catch(() => undefined); reader.releaseLock(); }
            else if (response?.body !== undefined && response.body !== null) await response.body.cancel().catch(() => undefined);
            active = undefined; physical = false; release();
          }
        } });
      } });
      return result;
    } catch (error) { clearPoolServerAllowConfiguration(captured); dependency.release(); throw error; }
  } finally { for (const value of owned) value.fill(0); }
}
function hostHistory(config: BrowserRunnerInstallation) {
  const call = (identity: sdk.IndexedDBPoolIdentity, epoch: bigint, action: string, fields: object = {}) => {
    const request = new XMLHttpRequest(); request.open("POST", config.host_endpoint, false); request.setRequestHeader("content-type", "application/json");
    request.send(JSON.stringify({ capability: config.host_capability, authority: identity.authority, store_id: base64(identity.storeID), generation: identity.generation.toString(), epoch: epoch.toString(), action, ...fields }));
    if (request.status !== 200 || request.responseText !== '{"status":"committed"}') throw new sdk.IndexedDBPoolError("history_unknown");
  };
  return {
    check: (identity: sdk.IndexedDBPoolIdentity, epoch: bigint, provisioning: boolean) => call(identity, epoch, "check", { provisioning }),
    checkRecord: (identity: sdk.IndexedDBPoolIdentity, epoch: bigint, key: Uint8Array, projection: Uint8Array) => call(identity, epoch, "record", { key: base64(key), projection: base64(projection) }),
    checkRecords: (identity: sdk.IndexedDBPoolIdentity, epoch: bigint, count: number) => call(identity, epoch, "records", { count }),
    reserveSpend: (identity: sdk.IndexedDBPoolIdentity, epoch: bigint, count: number, key: Uint8Array, projection: Uint8Array) => call(identity, epoch, "reserve", { count, key: base64(key), projection: base64(projection) }),
    retire: (identity: sdk.IndexedDBPoolIdentity) => call(identity, 1n, "retire"),
  };
}
export async function installBrowserRunner(config: BrowserRunnerInstallation, raw: string) {
  if (location.origin !== config.application_origin || config.deployment.applicationOrigin !== location.origin || config.host_endpoint !== "/runner/history" || config.bootstrap_endpoint !== "/runner/bootstrap") throw new Error("runner installation origin mismatch");
  if (hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw)))) !== config.material_sha256) throw new Error("runner material differs from original installation");
  const material = JSON.parse(raw);
  if (material.wire_revision !== 4 || material.role !== 0 || material.source !== "preauthorized_pool" || material.identity_seed !== config.identity_seed || material.dh_seed !== config.dh_seed) throw new Error("unsupported installed runner material");
  if (config.carrier === "webtransport" && (!Number.isSafeInteger(config.carrier_application_streams) || config.carrier_application_streams! < Number(config.limits.maxStreams) || config.carrier_application_streams! > 4096)) throw new Error("original native stream capacity does not cover the complete signed installation");
  const limit = new sdk.ResourceVector(config.resource_limit.map(BigInt));
  const root = new sdk.ResourceRoot({ profileRevision: hex(bytes(config.profile_revision,32)), limit, accounts: 2048, reservations: 4096, references: 8192, rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const start = performance.now(), now = BigInt(Date.now()), incarnation = hex(crypto.getRandomValues(new Uint8Array(16)));
  const environment = sdk.createTransportEnvironment({ root, limit, tenantLimit: limit, tenantID: hex(bytes(config.tenant_id,16)), environmentID: hex(crypto.getRandomValues(new Uint8Array(16))), runtimeBytes: 1024n,
    namespaces: config.namespaces.length, sources: 1, acquisitions: 1, materials: 4, sessions: 1, dependencies: 16, acquireMS: 10000n, cleanupMS: 10000,
    clock: { profile: { rate: new sdk.ClockRate(100n, 1000000n, 1n), maxWidthMS: 200n, maxAgeMS: 60000n, maxRoundTripMS: 10000n }, initial: () => ({ lowerMS: now, upperMS: now + 50n }), tick: () => ({ milliseconds: BigInt(Math.floor(performance.now() - start)), incarnation }) }, random: output => { crypto.getRandomValues(output); } });
  let notificationReceived = false;
  let notificationWait: { resolve(): void; reject(error: Error): void; detach(): void } | undefined;
  const history = hostHistory(config), identity = { authority: config.spend_authority, storeID: bytes(config.store_id, 32), generation: BigInt(config.store_generation) };
  const backing = sdk.createIndexedDBPoolBacking(environment, config.database_name, { maxRecords: 4, maxRecordBytes: 65536, transactionMS: 10000n, runtimeBytes: 1024n, providerRuntimeBytes: 1048576n, storageBytes: 1048576n });
  let store: sdk.IndexedDBPoolStore | undefined, plan: sdk.HandlerPlan | undefined, session: sdk.Session | undefined;
  let clearMaterial: () => void = () => undefined;
  let closing: Promise<void> | undefined;
  const close = () => closing ??= (async () => {
    notificationWait?.detach(); notificationWait?.reject(new Error("closed")); notificationWait = undefined;
    await session?.close(); plan?.close(); await environment.close(); store?.close();
    if (store !== undefined && !store.cleanupComplete()) throw new Error("original store cleanup incomplete");
    history.retire(identity);
    await new Promise<void>((resolve, reject) => { const request = indexedDB.deleteDatabase(config.database_name); request.onsuccess = () => resolve(); request.onerror = () => reject(request.error); request.onblocked = () => reject(new Error("IDB removal blocked")); });
    await backing.releaseRemoved(); const cleanup = await environment.waitCleanup(); if (cleanup.status !== "complete") throw new Error("original Environment cleanup incomplete"); clearMaterial(); root.close();
  })();
  try {
    store = await sdk.openIndexedDBPoolStore(backing, { create: true, identity, continuity: history, bindings: [{ tenant: config.policy.tenant, issuer: bytes(config.issuer_key_id, 16) }] });
    const identitySeed = bytes(config.identity_seed, 32), dhSeed = bytes(config.dh_seed, 32);
    const encoded = new Uint8Array(48); encoded.set([48,46,2,1,0,48,5,6,3,43,101,112,4,34,4,32]); encoded.set(identitySeed,16);
    const identityKey = await crypto.subtle.importKey("pkcs8", encoded, "Ed25519", true, ["sign"]); encoded.fill(0); identitySeed.fill(0);
    const b64url = (wire: Uint8Array) => base64(wire).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
    const curve = material.profile === "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1" ? "X25519" : material.profile === "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1" ? "P-256" : undefined;
    if (curve === undefined) throw new Error("unsupported installed crypto profile");
    const publicKey = curve === "X25519" ? x25519.getPublicKey(dhSeed) : p256.getPublicKey(dhSeed, false);
    const noiseKey = await crypto.subtle.importKey("jwk", curve === "X25519" ? { kty: "OKP", crv: curve, x: b64url(publicKey), d: b64url(dhSeed), ext: true } : { kty: "EC", crv: curve, x: b64url(publicKey.subarray(1,33)), y: b64url(publicKey.subarray(33)), d: b64url(dhSeed), ext: true }, curve === "X25519" ? curve : { name: "ECDH", namedCurve: curve }, true, ["deriveBits"]); dhSeed.fill(0);
    const codec = sdk.bytesMessageCodec({ schemaDigest: bytes(config.service_schema_digest,32), revision: "1", maxMessageBytes: config.max_message_bytes });
    if (config.application_schema !== undefined && config.application_schema !== "echo" && config.application_schema !== "parity") throw new Error("unsupported original application installation");
    const parity = config.application_schema === "parity";
    if (parity && (config.service_namespace !== "flowersec.parity" || config.max_message_bytes !== 4096 || config.service_notification_contract === undefined)) throw new Error("original parity application contract missing");
    const unary = (typeID: number) => new sdk.MethodDefinition({ typeID, shape: "unary", unarySemantics: "transient", request: codec, response: codec,
      requestMaxBytes: config.max_message_bytes, minResponseLimitBytes: 0, maxResponseBytes: config.max_message_bytes, restartFlush: false });
    const method = unary(parity ? 7001 : 1);
    const notificationMethod = parity ? new sdk.MethodDefinition<Uint8Array, Uint8Array, "notify", "observation">({ typeID: 7002, shape: "notify", notifySemantics: "observation",
      request: codec, requestMaxBytes: config.max_message_bytes, responseRevision: "1", restartFlush: false }) : undefined;
    const completionMethod = parity ? unary(7003) : undefined;
    const datagramBarrierMethod = parity ? unary(7005) : undefined;
    const methods: Record<string, sdk.MethodDefinition<Uint8Array, Uint8Array>> = { echo: method };
    if (notificationMethod !== undefined && completionMethod !== undefined && datagramBarrierMethod !== undefined) { methods.notify = notificationMethod; methods.completion = completionMethod; methods.datagramBarrier = datagramBarrierMethod; }
    const definition = new sdk.ServiceDefinition({ namespace: config.service_namespace, methods });
    const notificationMethods = notificationMethod === undefined ? [] : [{ namespace: config.service_namespace, method: notificationMethod,
      contract: bytes(config.service_notification_contract!,65536), permission: "allowed" as const }];
    const installedContracts = new Map<number, Uint8Array>();
    if (parity) {
      if (config.service_contracts?.length !== 4) throw new Error("original bidirectional parity contracts are missing");
      for (const record of config.service_contracts) {
        if (![7001,7002,7003,7005].includes(record.type_id) || installedContracts.has(record.type_id)) throw new Error("original parity contract set differs");
        installedContracts.set(record.type_id, bytes(record.contract,65536));
      }
      if (base64(installedContracts.get(7002)!) !== config.service_notification_contract) throw new Error("original parity observation contract differs");
    }
    const parityValue = (request: Uint8Array, expected: string) => {
      const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(request));
      if (value === null || typeof value !== "object" || value.value !== expected) throw new Error("invalid parity application request");
    };
    const unaryHandlers = parity ? [method,completionMethod!,datagramBarrierMethod!].map(selected => ({ namespace: config.service_namespace, method: selected, contract: installedContracts.get(selected.typeID)!,
      handler: async (context: sdk.ApplicationContext, request: Uint8Array) => {
        parityValue(request, selected === method ? "ping" : selected === completionMethod ? "complete" : "datagram-ready");
        if (selected === completionMethod) {
          if (session === undefined) throw new Error("original parity Session is unavailable");
          await session.rekey({ signal: context.signal }); await session.probeLiveness({ signal: context.signal });
        }
        return request;
      }, options: { workClass: "short" as const, maxConcurrentCalls: 2, applicationBytes: 16384n, authorization: "authenticated" as const } })) : [];
    const notificationHandlers = notificationMethod === undefined ? [] : [{ namespace: config.service_namespace, method: notificationMethod, contract: installedContracts.get(7002)!,
      handler: (_context: sdk.ApplicationContext, request: Uint8Array) => {
        parityValue(request,"notify"); notificationReceived = true;
        const waiter = notificationWait; notificationWait = undefined; waiter?.detach(); waiter?.resolve();
      }, options: { workClass: "short" as const, applicationBytes: 16384n, authorization: "authenticated" as const, applicationTimeoutMS: 10000n } }];
    try {
      plan = sdk.createHandlerPlan(environment, { applicationBytes: 16384n, services: { profile: "services", query: { typeID: config.service_query_type, contractDigest: bytes(config.service_query_digest,32) }, definitions: [definition], maxMethods: parity ? 4 : 1, maxCaptureBytes: 1048576, notificationMethods, unaryHandlers, notificationHandlers,
        queryPermissions: Object.values(methods).map(selected => ({ namespace: config.service_namespace, method: selected, permission: "allowed" as const })) },
        streams: ["release-bulk", "native-isolation", "capacity-bidi"].map(kind => ({ kind, handler: async () => { throw new Error("runner does not accept inbound application streams"); }, authorize: () => false, options: { applicationBytes: 16384n, maxConcurrentStreams: config.max_streams, maxAuthorizing: config.max_streams, metadataNamespaces: [{ namespace: "application/json", version: 1 }] } })) });
    } finally { for (const contract of installedContracts.values()) contract.fill(0); }
    const deployment = { ...config.deployment, routeDigest: bytes(config.deployment.routeDigest,32), notBeforeMS: BigInt(config.deployment.notBeforeMS), notAfterMS: BigInt(config.deployment.notAfterMS) };
    const limits = Object.fromEntries(Object.entries(config.limits).map(([key,value]) => [key, typeof value === "string" ? BigInt(value) : value])) as unknown as sdk.BrowserWSSClientConfig["limits"];
    const poolServerAllow = runnerServerAllow(environment, config, material.tunnels ?? []);
    const common = { identityKey, noiseKey, poolStore: store, handlerPlan: plan, limits, ...(poolServerAllow === undefined ? {} : { poolServerAllow }) };
    const client = config.carrier === "wss" ? await sdk.configureBrowserWSS(environment, { ...common, carrier: { deployment: deployment as unknown as sdk.BrowserWSSDeployment, queueMessages: 8, sendBufferBytes: 65544, runtimeBytes: BigInt(config.carrier_runtime_bytes), providerRuntimeBytes: BigInt(config.provider_runtime_bytes) } }) : await sdk.configureBrowserWebTransport(environment, { ...common, carrier: { deployment: deployment as unknown as sdk.BrowserWebTransportDeployment, applicationStreams: config.carrier_application_streams!, streamBufferBytes: 65544, runtimeBytes: BigInt(config.carrier_runtime_bytes), providerRuntimeBytes: BigInt(config.provider_runtime_bytes), providerStreamBytes: BigInt(config.provider_stream_bytes) } });
    for (const [index, record] of config.namespaces.entries()) {
      const namespace = client.namespace({ tenant: record.tenant, authority: record.authority, rootKeyID: bytes(record.root_key_id,16), rootPublicKey: bytes(record.root_public_key,32), maxTrustLifetimeMS: 120000n, bootstrapMS: 10000n, stateBytes: 65536, stateNodes: 131072 });
      await namespace.fetchBootstrap(async (request, responseDestination, stateDestination) => {
        const response = await fetch(config.bootstrap_endpoint, { method: "POST", signal: request.signal,
          headers: { "content-type": "application/json" }, body: JSON.stringify({ capability: config.host_capability, index, nonce: base64(request.nonce) }) });
        try {
          if (!response.ok) throw new Error("original bootstrap unavailable");
          const reply = await response.json(), signed = bytes(reply.response,65536), state = bytes(reply.state,65536);
          try {
            responseDestination.set(signed); stateDestination.set(state);
            return { responseBytes: signed.length, stateBytes: state.length };
          } finally { signed.fill(0); state.fill(0); }
        } finally { await response.body?.cancel().catch(() => undefined); }
      });
      if (namespace.activeVersion()[0] !== BigInt(record.generation)) throw new Error("installed namespace generation mismatch");
    }
    const owned = { artifact: bytes(material.artifact,65536), activation: bytes(material.activation,65536), clientCertificate: bytes(material.client_certificate,16384), serverCertificate: bytes(material.server_certificate,16384) };
    const tunnel = material.tunnels?.find((entry: { role: number; candidate_index: number }) => entry.role === 0 && entry.candidate_index === 0);
    const tunnelGrant = tunnel === undefined ? new Uint8Array() : bytes(tunnel.grant,65536), relayCertificate = tunnel === undefined ? new Uint8Array() : bytes(tunnel.relay_certificate,16384);
    clearMaterial = () => { for (const value of [...Object.values(owned), tunnelGrant, relayCertificate]) value.fill(0); };
    const source = client.registerPoolSource(config.policy, async (request, destination) => {
      if (request.signal.aborted) throw new Error("canceled"); for (const key of ["artifact", "activation", "clientCertificate", "serverCertificate"] as const) destination[key].set(owned[key]);
      destination.tunnelGrant.set(tunnelGrant); destination.relayCertificate.set(relayCertificate);
      return { artifact: owned.artifact.length, activation: owned.activation.length, clientCertificate: owned.clientCertificate.length, serverCertificate: owned.serverCertificate.length, candidateIndex: 0, tunnelGrant: tunnelGrant.length, relayCertificate: relayCertificate.length };
    });
    return {
      environment, close,
      async connect(signal?: AbortSignal) {
        session = await sdk.connect(environment, source, { independent_reliable_read_progress: false, bound_stream_input_isolation: false, datagram: false, local_consumer_tls13_verification: false, application_profile: "services" }, signal === undefined ? {} : { signal }); return session;
      },
      async bindEcho(signal?: AbortSignal) {
        if (session === undefined) throw new Error("runner Session missing");
        return await session.bindService(definition, { ...(signal === undefined ? {} : { signal }), target: { authority: config.policy.authorities[0]!, tenant: config.policy.tenant, audience: config.policy.audience, localSubject: config.policy.clientSubject, peers: [{ subject: config.policy.serverSubject, identityDigest: config.server_identity_digest }] }, maximumOfferWindowMS: 10000n });
      }, method, notificationMethod, completionMethod, datagramBarrierMethod,
      async waitNotification(signal: AbortSignal) {
        if (!parity) throw new Error("original parity application is unavailable");
        if (signal.aborted) throw new Error("canceled");
        if (notificationReceived) return;
        if (notificationWait !== undefined) throw new Error("notification observation is busy");
        await new Promise<void>((resolve,reject) => {
          const cancel = () => { notificationWait = undefined; signal.removeEventListener("abort",cancel); reject(new Error("canceled")); };
          notificationWait = { resolve, reject, detach: () => signal.removeEventListener("abort",cancel) };
          signal.addEventListener("abort",cancel,{ once: true });
          if (signal.aborted) cancel();
        });
      },
      async spendCount() { return await new Promise<number>((resolve,reject) => { const request = indexedDB.open(config.database_name); request.onerror = () => reject(request.error); request.onsuccess = () => { const db=request.result, tx=db.transaction("spend","readonly"), count=tx.objectStore("spend").count(); tx.oncomplete=()=>{db.close();resolve(count.result);};tx.onabort=()=>{db.close();reject(tx.error);}; }; }); },
    };
  } catch (error) { await close().catch(() => undefined); throw error; }
}
