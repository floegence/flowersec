import { defineRuntimeCapabilityDescriptorV3, type RuntimeCapabilityDescriptorV3, type RuntimeCapabilityTupleV3 } from "./capability.js";
import type { CanonicalArtifactCandidateV3 } from "./artifact.js";
import { snapshotTransportSecurityPolicyV3, TransportFailureV3 } from "./security.js";
import {
  adaptWebTransportCarrierSessionV3,
  hasWebTransportConstructorSurfaceV3,
  type WebTransportSessionLikeV3,
} from "./webTransportCarrier.js";
import type { NativeCarrierSessionV3 } from "./carrier.js";
import { FLOWERSEC_V3_PATHS, FLOWERSEC_V3_WIRE_PROFILES } from "./transportConstants.js";

const PIN_BROWSER_VERSION = "151.0.7922.34";

type BrowserFeaturesV3 = Readonly<{
  WebSocket?: unknown;
  WebTransport?: unknown;
  navigator?: Readonly<{
    userAgentData?: Readonly<{
      getHighEntropyValues(hints: readonly string[]): Promise<unknown>;
    }>;
  }>;
}>;

type WebTransportLikeV3 = Readonly<{
  ready: Promise<void>;
  close(options?: Readonly<{ closeCode?: number; reason?: string }>): void;
}>;

type WebTransportConstructorV3 = new (
  url: string,
  options?: Readonly<{
    serverCertificateHashes: readonly Readonly<{ algorithm: "sha-256"; value: ArrayBuffer }>[];
  }>,
) => WebTransportLikeV3;

const webSocketTuples = tuplesFor("websocket", false, ["ca"]);
const webTransportCATuples = tuplesFor("webtransport", true, ["ca"]);
const webTransportPinTuples = tuplesFor("webtransport", true, ["ca", "pin"]);

export class BrowserRuntimeCapabilityRegistryV3 {
  readonly #features: BrowserFeaturesV3;
  readonly #hasWebSocket: boolean;
  readonly #hasWebTransport: boolean;
  #pinState: "enabled" | "ca_only";

  private constructor(features: BrowserFeaturesV3, pinEnabled: boolean) {
    this.#features = features;
    this.#hasWebSocket = typeof features.WebSocket === "function";
    this.#hasWebTransport = hasWebTransportConstructorSurfaceV3(features.WebTransport);
    this.#pinState = pinEnabled ? "enabled" : "ca_only";
  }

  static async create(
    features: BrowserFeaturesV3 = globalThis as unknown as BrowserFeaturesV3,
  ): Promise<BrowserRuntimeCapabilityRegistryV3> {
    return new BrowserRuntimeCapabilityRegistryV3(features, await exactChromiumPinProvider(features));
  }

  snapshot(): RuntimeCapabilityDescriptorV3 {
    const tuples: RuntimeCapabilityTupleV3[] = [];
    const unsupported: Array<{ carrier: "raw_quic" | "websocket" | "webtransport"; reason: string }> = [
      { carrier: "raw_quic", reason: "browser_no_raw_udp" },
    ];
    if (this.#hasWebSocket) tuples.push(...webSocketTuples);
    else unsupported.push({ carrier: "websocket", reason: "browser_websocket_api_unavailable" });
    if (this.#hasWebTransport) {
      tuples.push(...(this.#pinState === "enabled" ? webTransportPinTuples : webTransportCATuples));
    } else {
      unsupported.push({ carrier: "webtransport", reason: "browser_webtransport_api_unavailable" });
    }
    unsupported.sort((left, right) => left.carrier < right.carrier ? -1 : left.carrier > right.carrier ? 1 : 0);
    return defineRuntimeCapabilityDescriptorV3("browser", tuples, unsupported);
  }

  pinEnabled(): boolean {
    return this.#pinState === "enabled";
  }

  invalidatePinSupport(): boolean {
    if (this.#pinState === "ca_only") return false;
    this.#pinState = "ca_only";
    return true;
  }

  webTransportConstructor(): WebTransportConstructorV3 | undefined {
    return hasWebTransportConstructorSurfaceV3(this.#features.WebTransport)
      ? this.#features.WebTransport as WebTransportConstructorV3
      : undefined;
  }
}

export async function createBrowserWebTransportV3(
  candidate: CanonicalArtifactCandidateV3,
  attemptNowUnixSeconds: number,
  capabilitySnapshot: RuntimeCapabilityDescriptorV3,
  registry: BrowserRuntimeCapabilityRegistryV3,
  signal?: AbortSignal,
): Promise<WebTransportLikeV3> {
  if (candidate.carrier !== "webtransport") throw new TransportFailureV3("invalid_artifact");
  const path = pathFromProfile(candidate.wire_profile);
  validateNormalizedBrowserURL(candidate.normalized_url, path);
  const tuple = capabilitySnapshot.tuples.find((entry) =>
    entry.carrier === "webtransport" && entry.networkMode === "dial" && entry.path === path);
  const modes = tuple?.securityModes ?? [];
  const policy = snapshotTransportSecurityPolicyV3(candidate.tls, attemptNowUnixSeconds, modes);
  if (policy.mode === "pin" && !registry.pinEnabled()) throw new TransportFailureV3("tls_unsupported");
  const Constructor = registry.webTransportConstructor();
  if (Constructor === undefined) throw new TransportFailureV3("tls_unsupported");
  if (signal?.aborted === true) throw signal.reason;
  let transport: WebTransportLikeV3;
  try {
    transport = policy.mode === "ca"
      ? new Constructor(candidate.normalized_url)
      : new Constructor(candidate.normalized_url, {
          serverCertificateHashes: policy.activeLeafDerSHA256.map((value) => ({
            algorithm: "sha-256" as const,
            value: exactArrayBuffer(value),
          })),
        });
  } catch (error) {
    if (policy.mode === "pin" && isNotSupportedError(error)) {
      registry.invalidatePinSupport();
      throw new TransportFailureV3("tls_unsupported", undefined, error);
    }
    throw new TransportFailureV3("connection_failed", policy.mode === "pin" ? "browser_pin_opaque" : undefined, error);
  }
  try {
    await raceAbort(transport.ready, signal);
    return transport;
  } catch (error) {
    try { transport.close({ closeCode: 6, reason: "WebTransport start failed" }); } catch { /* best effort */ }
    if (error instanceof BrowserRuntimeAbortV3) throw error.reason;
    throw new TransportFailureV3(
      "connection_failed",
      policy.mode === "pin" ? "browser_pin_opaque" : undefined,
      error,
    );
  }
}

export async function createBrowserWebTransportCarrierV3(
  candidate: CanonicalArtifactCandidateV3,
  attemptNowUnixSeconds: number,
  capabilitySnapshot: RuntimeCapabilityDescriptorV3,
  registry: BrowserRuntimeCapabilityRegistryV3,
  inboundBidirectionalStreamCapacity: number,
  signal?: AbortSignal,
): Promise<NativeCarrierSessionV3> {
  const path = pathFromProfile(candidate.wire_profile);
  const transport = await createBrowserWebTransportV3(
    candidate,
    attemptNowUnixSeconds,
    capabilitySnapshot,
    registry,
    signal,
  );
  try {
    return adaptWebTransportCarrierSessionV3(
      transport as unknown as WebTransportSessionLikeV3,
      { path, inboundBidirectionalStreamCapacity },
    ) as unknown as NativeCarrierSessionV3;
  } catch (error) {
    try { transport.close({ closeCode: 6, reason: "WebTransport adapter failed" }); } catch { /* best effort */ }
    throw error;
  }
}

async function exactChromiumPinProvider(features: BrowserFeaturesV3): Promise<boolean> {
  if (!hasWebTransportConstructorSurfaceV3(features.WebTransport)) return false;
  const provider = features.navigator?.userAgentData;
  if (provider === undefined || typeof provider.getHighEntropyValues !== "function") return false;
  let value: unknown;
  try {
    value = await provider.getHighEntropyValues(["fullVersionList"]);
  } catch {
    return false;
  }
  if (typeof value !== "object" || value === null) return false;
  const list = (value as { fullVersionList?: unknown }).fullVersionList;
  if (!Array.isArray(list)) return false;
  const chromium = list.filter((entry) => typeof entry === "object" && entry !== null &&
    (entry as { brand?: unknown }).brand === "Chromium");
  if (chromium.length !== 1) return false;
  const version = (chromium[0] as { version?: unknown }).version;
  return typeof version === "string" && /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(version) &&
    version === PIN_BROWSER_VERSION;
}

function tuplesFor(
  carrier: "websocket" | "webtransport",
  datagrams: boolean,
  securityModes: readonly ("ca" | "pin")[],
): readonly RuntimeCapabilityTupleV3[] {
  return Object.freeze([
    { carrier, datagrams, migration: false, networkMode: "dial", path: "direct", reliableStreams: true, securityModes, sessionRole: "client" },
    { carrier, datagrams, migration: false, networkMode: "dial", path: "tunnel", reliableStreams: true, securityModes, sessionRole: "client" },
    { carrier, datagrams, migration: false, networkMode: "dial", path: "tunnel", reliableStreams: true, securityModes, sessionRole: "server" },
  ]);
}

function validateNormalizedBrowserURL(raw: string, path: "direct" | "tunnel"): void {
  let parsed: URL;
  try { parsed = new URL(raw); } catch { throw new TransportFailureV3("invalid_artifact"); }
  const expectedPath = FLOWERSEC_V3_PATHS.webtransport[path];
  if (parsed.href !== raw || parsed.protocol !== "https:" || parsed.username !== "" || parsed.password !== "" ||
      parsed.pathname !== expectedPath || parsed.search !== "" || parsed.hash !== "") {
    throw new TransportFailureV3("invalid_artifact");
  }
}

function pathFromProfile(profile: string): "direct" | "tunnel" {
  if (profile === FLOWERSEC_V3_WIRE_PROFILES.direct) return "direct";
  if (profile === FLOWERSEC_V3_WIRE_PROFILES.tunnel) return "tunnel";
  throw new TransportFailureV3("invalid_artifact");
}

function exactArrayBuffer(value: Uint8Array): ArrayBuffer {
  return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;
}

function isNotSupportedError(error: unknown): boolean {
  return error instanceof DOMException ? error.name === "NotSupportedError" :
    typeof error === "object" && error !== null && (error as { name?: unknown }).name === "NotSupportedError";
}

class BrowserRuntimeAbortV3 {
  constructor(readonly reason: unknown) {}
}

async function raceAbort<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (signal === undefined) return await promise;
  if (signal.aborted) throw new BrowserRuntimeAbortV3(signal.reason);
  return await new Promise<T>((resolve, reject) => {
    const abort = () => {
      signal.removeEventListener("abort", abort);
      reject(new BrowserRuntimeAbortV3(signal.reason));
    };
    signal.addEventListener("abort", abort, { once: true });
    void promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}
