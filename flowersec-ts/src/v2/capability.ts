import { sha256 } from "@noble/hashes/sha256";

import type { CarrierKind, PathKind } from "./contract.js";

export type NetworkModeV2 = "dial" | "listen";

export type SessionRoleV2 = "client" | "server";

export type RuntimeCapabilityTupleV2 = Readonly<{
  carrier: CarrierKind;
  networkMode: NetworkModeV2;
  path: PathKind;
  sessionRole: SessionRoleV2;
}>;

export type UnsupportedRuntimeCarrierV2 = Readonly<{
  carrier: CarrierKind;
  reason: string;
}>;

export type RuntimeCapabilityDescriptorV2 = Readonly<{
  language: string;
  runtime: string;
  schemaVersion: 2;
  tuples: readonly RuntimeCapabilityTupleV2[];
  unsupported: readonly UnsupportedRuntimeCarrierV2[];
}>;

export type BrowserRuntimeFeaturesV2 = Readonly<{
  WebSocket?: unknown;
  WebTransport?: unknown;
}>;

const encoder = new TextEncoder();
const carriers: readonly CarrierKind[] = Object.freeze(["raw_quic", "websocket", "webtransport"]);
const registryToken = /^[a-z][a-z0-9_]{0,127}$/;
const digestLabel = encoder.encode("flowersec-v2-runtime-capability\0");

function tuple(
  carrier: CarrierKind,
  networkMode: NetworkModeV2,
  path: PathKind,
  sessionRole: SessionRoleV2,
): RuntimeCapabilityTupleV2 {
  return Object.freeze({ carrier, networkMode, path, sessionRole });
}

function unsupported(carrier: CarrierKind, reason: string): UnsupportedRuntimeCarrierV2 {
  return Object.freeze({ carrier, reason });
}

function descriptor(
  runtime: string,
  tuples: readonly RuntimeCapabilityTupleV2[],
  unsupportedCarriers: readonly UnsupportedRuntimeCarrierV2[],
): RuntimeCapabilityDescriptorV2 {
  const value: RuntimeCapabilityDescriptorV2 = {
    language: "typescript",
    runtime,
    schemaVersion: 2,
    tuples: Object.freeze([...tuples]),
    unsupported: Object.freeze([...unsupportedCarriers]),
  };
  validateRuntimeCapabilityDescriptorV2(value);
  return Object.freeze(value);
}

export const BROWSER_RUNTIME_CAPABILITY_V2 = descriptor(
  "browser",
  [
    tuple("websocket", "dial", "direct", "client"),
    tuple("websocket", "dial", "tunnel", "client"),
    tuple("websocket", "dial", "tunnel", "server"),
    tuple("webtransport", "dial", "direct", "client"),
    tuple("webtransport", "dial", "tunnel", "client"),
    tuple("webtransport", "dial", "tunnel", "server"),
  ],
  [unsupported("raw_quic", "browser_no_raw_udp")],
);

export const NODE_RUNTIME_CAPABILITY_V2 = descriptor(
  "node",
  [],
  [
    unsupported("raw_quic", "no_production_grade_node_quic_runtime"),
    unsupported("websocket", "transport_v2_websocket_adapter_not_committed"),
    unsupported("webtransport", "no_production_grade_node_quic_runtime"),
  ],
);

export function detectBrowserRuntimeCapabilityV2(
  runtime: BrowserRuntimeFeaturesV2 = globalThis as BrowserRuntimeFeaturesV2,
): RuntimeCapabilityDescriptorV2 {
  const available = new Set<CarrierKind>();
  if (typeof runtime.WebSocket === "function") available.add("websocket");
  if (typeof runtime.WebTransport === "function") available.add("webtransport");
  const tuples = BROWSER_RUNTIME_CAPABILITY_V2.tuples.filter(({ carrier }) => available.has(carrier));
  const unavailable = [...BROWSER_RUNTIME_CAPABILITY_V2.unsupported];
  if (!available.has("websocket")) {
    unavailable.push(unsupported("websocket", "browser_websocket_api_unavailable"));
  }
  if (!available.has("webtransport")) {
    unavailable.push(unsupported("webtransport", "browser_webtransport_api_unavailable"));
  }
  unavailable.sort(compareUnsupported);
  return descriptor("browser", tuples, unavailable);
}

export function encodeRuntimeCapabilityDescriptorV2(descriptor: RuntimeCapabilityDescriptorV2): string {
  validateRuntimeCapabilityDescriptorV2(descriptor);
  return JSON.stringify({
    language: descriptor.language,
    runtime: descriptor.runtime,
    schemaVersion: descriptor.schemaVersion,
    tuples: descriptor.tuples.map(({ carrier, networkMode, path, sessionRole }) => ({
      carrier, networkMode, path, sessionRole,
    })),
    unsupported: descriptor.unsupported.map(({ carrier, reason }) => ({ carrier, reason })),
  });
}

export function decodeRuntimeCapabilityDescriptorV2(raw: string): RuntimeCapabilityDescriptorV2 {
  const parsed = JSON.parse(raw) as unknown;
  const value = decodeDescriptor(parsed);
  const canonical = encodeRuntimeCapabilityDescriptorV2(value);
  if (canonical !== raw) throw new TypeError("runtime capability descriptor is not canonical JSON");
  return value;
}

export function runtimeCapabilityDigestV2(descriptor: RuntimeCapabilityDescriptorV2): Uint8Array {
  const canonical = encoder.encode(encodeRuntimeCapabilityDescriptorV2(descriptor));
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, canonical.length);
  const preimage = new Uint8Array(digestLabel.length + length.length + canonical.length);
  preimage.set(digestLabel, 0);
  preimage.set(length, digestLabel.length);
  preimage.set(canonical, digestLabel.length + length.length);
  return sha256(preimage);
}

export function runtimeCapabilityDigestHexV2(descriptor: RuntimeCapabilityDescriptorV2): string {
  return Array.from(runtimeCapabilityDigestV2(descriptor), (value) => value.toString(16).padStart(2, "0")).join("");
}

export function validateRuntimeCapabilityDescriptorV2(descriptor: RuntimeCapabilityDescriptorV2): void {
  if (descriptor.schemaVersion !== 2 || !registryToken.test(descriptor.language) ||
      !registryToken.test(descriptor.runtime) || descriptor.tuples.length + descriptor.unsupported.length === 0) {
    throw new TypeError("invalid runtime capability descriptor header");
  }
  const supported = new Set<CarrierKind>();
  let previousTuple: RuntimeCapabilityTupleV2 | undefined;
  for (const current of descriptor.tuples) {
    validateTuple(current);
    if (previousTuple !== undefined && compareTuple(previousTuple, current) >= 0) {
      throw new TypeError("runtime capability tuples must be unique and canonically sorted");
    }
    supported.add(current.carrier);
    previousTuple = current;
  }
  const unavailable = new Set<CarrierKind>();
  let previousUnsupported: UnsupportedRuntimeCarrierV2 | undefined;
  for (const current of descriptor.unsupported) {
    if (!carriers.includes(current.carrier) || !registryToken.test(current.reason) || supported.has(current.carrier)) {
      throw new TypeError("invalid unsupported runtime carrier");
    }
    if (previousUnsupported !== undefined && compareUnsupported(previousUnsupported, current) >= 0) {
      throw new TypeError("unsupported runtime carriers must be unique and canonically sorted");
    }
    unavailable.add(current.carrier);
    previousUnsupported = current;
  }
  for (const carrier of carriers) {
    if (supported.has(carrier) === unavailable.has(carrier)) {
      throw new TypeError(`runtime capability must support or explicitly reject ${carrier}`);
    }
  }
}

function decodeDescriptor(input: unknown): RuntimeCapabilityDescriptorV2 {
  const object = exactObject(input, ["language", "runtime", "schemaVersion", "tuples", "unsupported"]);
  if (!Array.isArray(object.tuples) || !Array.isArray(object.unsupported)) {
    throw new TypeError("runtime capability collections must be arrays");
  }
  const tuples = object.tuples.map((input) => {
    const value = exactObject(input, ["carrier", "networkMode", "path", "sessionRole"]);
    return tuple(
      requireCarrier(value.carrier),
      requireNetworkMode(value.networkMode),
      requirePath(value.path),
      requireSessionRole(value.sessionRole),
    );
  });
  const unsupportedCarriers = object.unsupported.map((input) => {
    const value = exactObject(input, ["carrier", "reason"]);
    if (typeof value.reason !== "string") throw new TypeError("unsupported reason must be a string");
    return unsupported(requireCarrier(value.carrier), value.reason);
  });
  if (typeof object.language !== "string" || typeof object.runtime !== "string" || object.schemaVersion !== 2) {
    throw new TypeError("invalid runtime capability descriptor header");
  }
  const result: RuntimeCapabilityDescriptorV2 = Object.freeze({
    language: object.language,
    runtime: object.runtime,
    schemaVersion: 2,
    tuples: Object.freeze(tuples),
    unsupported: Object.freeze(unsupportedCarriers),
  });
  validateRuntimeCapabilityDescriptorV2(result);
  return result;
}

function validateTuple(value: RuntimeCapabilityTupleV2): void {
  if (!carriers.includes(value.carrier) || !["dial", "listen"].includes(value.networkMode) ||
      !["direct", "tunnel"].includes(value.path) || !["client", "server"].includes(value.sessionRole)) {
    throw new TypeError("invalid runtime capability tuple");
  }
  const valid = value.path === "direct"
    ? (value.networkMode === "dial" && value.sessionRole === "client") ||
      (value.networkMode === "listen" && value.sessionRole === "server")
    : value.networkMode === "dial";
  if (!valid) throw new TypeError("invalid runtime capability deployment role");
}

function compareTuple(left: RuntimeCapabilityTupleV2, right: RuntimeCapabilityTupleV2): number {
  return compareStrings(
    [left.carrier, left.networkMode, left.sessionRole, left.path],
    [right.carrier, right.networkMode, right.sessionRole, right.path],
  );
}

function compareUnsupported(left: UnsupportedRuntimeCarrierV2, right: UnsupportedRuntimeCarrierV2): number {
  return left.carrier < right.carrier ? -1 : left.carrier > right.carrier ? 1 : 0;
}

function compareStrings(left: readonly string[], right: readonly string[]): number {
  for (let index = 0; index < left.length; index++) {
    if (left[index]! < right[index]!) return -1;
    if (left[index]! > right[index]!) return 1;
  }
  return 0;
}

function exactObject(input: unknown, keys: readonly string[]): Record<string, unknown> {
  if (typeof input !== "object" || input === null || Array.isArray(input)) throw new TypeError("expected object");
  const object = input as Record<string, unknown>;
  const actual = Object.keys(object).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError("runtime capability object has unknown or missing fields");
  }
  return object;
}

function requireCarrier(value: unknown): CarrierKind {
  if (typeof value !== "string" || !carriers.includes(value as CarrierKind)) throw new TypeError("invalid carrier");
  return value as CarrierKind;
}

function requireNetworkMode(value: unknown): NetworkModeV2 {
  if (value !== "dial" && value !== "listen") throw new TypeError("invalid network mode");
  return value;
}

function requireSessionRole(value: unknown): SessionRoleV2 {
  if (value !== "client" && value !== "server") throw new TypeError("invalid session role");
  return value;
}

function requirePath(value: unknown): PathKind {
  if (value !== "direct" && value !== "tunnel") throw new TypeError("invalid path");
  return value;
}
