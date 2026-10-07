import type { ClientSessionAdmission } from "../v4/runtime/sessionAdmission.js";
import type { V4EnvironmentRuntime, EnvironmentDependency } from "../v4/runtime/environment.js";
import type { ClientPreparationFields } from "../v4/runtime/credentialVerifier.js";
import { CredentialWork, requireCredential, equalCredential } from "../v4/runtime/credentialSupport.js";
import { BrowserWSSCarrier, browserWSSAdmissionCosts, type BrowserWebSocketOptions } from "./wssV4.js";

export interface LocalBrowserBridgeDeployment {
  readonly endpoint: string;
  readonly applicationOrigin: string;
  readonly routeDigest: Uint8Array;
  readonly notBeforeMS: bigint;
  readonly notAfterMS: bigint;
  readonly applicationAuthAssurance: "application_origin";
  /** Ambient Cookie/HTTP authentication belongs to this configured trusted
   * local service scope; it does not establish a secret per listening port. */
  readonly ambientCredentialScope: "trusted_local_services";
}
export interface LocalBrowserBridgeOptions extends Omit<BrowserWebSocketOptions, "deployment"> {
  readonly deployment: LocalBrowserBridgeDeployment;
}
function loopback(host: string): boolean {
  if (host === "[::1]") return true;
  const octets = host.split(".");
  return octets.length === 4 && octets[0] === "127" && octets.every(value => /^(0|[1-9][0-9]{0,2})$/u.test(value) && Number(value) <= 255);
}
export function captureLocalBrowserBridge(options: LocalBrowserBridgeOptions): LocalBrowserBridgeOptions {
  // This same-origin loopback WSS path needs only the synchronous WebSocket
  // feature check below. It deliberately avoids asynchronous User-Agent Client
  // Hints probes, which add no trust evidence and can outlive admission.
  const d = options.deployment;
  requireCredential(typeof globalThis.WebSocket === "function" && typeof globalThis.crypto?.subtle === "object" && typeof globalThis.location?.origin === "string", "configuration_capacity");
  requireCredential(d.applicationAuthAssurance === "application_origin" && d.ambientCredentialScope === "trusted_local_services", "configuration_capacity");
  requireCredential(typeof d.endpoint === "string" && typeof d.applicationOrigin === "string" && d.routeDigest instanceof Uint8Array && d.routeDigest.length === 32 &&
    typeof d.notBeforeMS === "bigint" && d.notBeforeMS >= 0n && typeof d.notAfterMS === "bigint" && d.notAfterMS > d.notBeforeMS && d.notAfterMS <= 0xffffffffffffffffn &&
    Number.isSafeInteger(options.queueMessages) && options.queueMessages >= 1 && options.queueMessages <= 64 && Number.isSafeInteger(options.sendBufferBytes) && options.sendBufferBytes >= 65544 && options.sendBufferBytes <= 16777224 &&
    typeof options.runtimeBytes === "bigint" && options.runtimeBytes > 0n && options.runtimeBytes <= 0xffffffffffffffffn &&
    typeof options.providerRuntimeBytes === "bigint" && options.providerRuntimeBytes > 0n && options.providerRuntimeBytes <= 0xffffffffffffffffn, "configuration_capacity");
  let endpoint: URL, origin: URL;
  try { endpoint = new URL(d.endpoint); origin = new URL(d.applicationOrigin); }
  catch { requireCredential(false, "configuration_capacity"); }
  const port = Number(endpoint.port);
  requireCredential(endpoint.href === d.endpoint && endpoint.protocol === "ws:" && endpoint.username === "" && endpoint.password === "" && endpoint.search === "" && endpoint.hash === "" &&
    !d.endpoint.includes("%") && loopback(endpoint.hostname) && Number.isSafeInteger(port) && port >= 1024 && port <= 65535 && endpoint.pathname === "/flowersec/v4/local" &&
    origin.origin === d.applicationOrigin && origin.protocol === "http:" && origin.hostname === endpoint.hostname && origin.port === endpoint.port && origin.origin === globalThis.location.origin, "configuration_capacity");
  return Object.freeze({ deployment: Object.freeze({ endpoint: d.endpoint, applicationOrigin: d.applicationOrigin, routeDigest: new Uint8Array(d.routeDigest),
    notBeforeMS: d.notBeforeMS, notAfterMS: d.notAfterMS, applicationAuthAssurance: d.applicationAuthAssurance, ambientCredentialScope: d.ambientCredentialScope }),
    queueMessages: options.queueMessages, sendBufferBytes: options.sendBufferBytes, runtimeBytes: options.runtimeBytes, providerRuntimeBytes: options.providerRuntimeBytes });
}
export async function prepareLocalBrowserBridge(environment: V4EnvironmentRuntime, fields: ClientPreparationFields, options: LocalBrowserBridgeOptions,
  signal?: AbortSignal, admission?: ClientSessionAdmission): Promise<BrowserWSSCarrier> {
  const d = options.deployment, now = environment.clock.sample().requireInterval();
  requireCredential(fields.accessClass === 1n && equalCredential(fields.routeDigest, d.routeDigest) && now.lowerMS >= d.notBeforeMS && now.upperMS < d.notAfterMS && globalThis.location.origin === d.applicationOrigin);
  const costs = browserWSSAdmissionCosts(fields.maxFrame, options, environment.resources.runtimeBytes), reference = admission?.take([costs[0]!])[0];
  let dependency: EnvironmentDependency;
  try { dependency = environment.admitDependency("local_browser_bridge", costs[0]![1], reference, admission); } finally { reference?.release(); }
  let work: CredentialWork | undefined, carrier: BrowserWSSCarrier | undefined;
  try {
    const ref = environment.reserveConnectionWork(costs[1]![0], costs[1]![1], admission);
    try { work = new CredentialWork(environment.resources, 16384, ref); } finally { ref.release(); }
    const route = work.parse(fields.route, "Route", 16384);
    try {
      const leg = route.field("direct_leg"), url = new URL(d.endpoint);
      requireCredential(route.uint("path_kind") === 0n && route.uint("access_class", leg, "Leg") === 1n && route.uint("carrier", leg, "Leg") === 1n &&
        route.uint("dialer_role", leg, "Leg") === 0n && route.uint("listener_role", leg, "Leg") === 1n && route.text("host", leg, "Leg") === url.hostname.replace(/^\[|\]$/gu, "") &&
        route.uint("port", leg, "Leg") === BigInt(url.port) && route.text("path", leg, "Leg") === "/flowersec/v4/local" && route.text("subprotocol", leg, "Leg") === "flowersec.local.v4" &&
        route.text("origin", leg, "Leg") === d.applicationOrigin);
    } finally { route.close(); work.close(); work = undefined; }
    carrier = new BrowserWSSCarrier(environment, dependency, options, Math.max(fields.maxFrame, 65536) + 8, fields.preparationDeadline, "flowersec.local.v4");
    await carrier.prepare(signal); return carrier;
  } catch (error) {
    work?.close();
    if (carrier !== undefined) await Promise.allSettled([carrier.close(), carrier.waitTermination()]);
    else dependency.release();
    throw error;
  }
}
