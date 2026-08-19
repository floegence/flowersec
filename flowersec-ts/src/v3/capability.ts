import { sha256 } from "@noble/hashes/sha2.js";

import { concatBytes, u32be } from "../utils/bin.js";
import type { CarrierKind, PathKind } from "../public/contract.js";
import { canonicalizeJCSV3, type JCSValue } from "./jcs.js";
import { preflightJSONV3 } from "./jsonPreflight.js";

export type TransportSecurityModeV3 = "ca" | "pin";
export type NetworkModeV3 = "dial" | "listen";
export type SessionRoleV3 = "client" | "server";

export type RuntimeCapabilityTupleV3 = Readonly<{
  carrier: CarrierKind;
  datagrams: boolean;
  migration: boolean;
  networkMode: NetworkModeV3;
  path: PathKind;
  reliableStreams: true;
  securityModes: readonly TransportSecurityModeV3[];
  sessionRole: SessionRoleV3;
}>;

export type UnsupportedRuntimeCarrierV3 = Readonly<{
  carrier: CarrierKind;
  reason: string;
}>;

export type RuntimeCapabilityDescriptorV3 = Readonly<{
  language: string;
  runtime: string;
  schemaVersion: 3;
  tuples: readonly RuntimeCapabilityTupleV3[];
  unsupported: readonly UnsupportedRuntimeCarrierV3[];
}>;

const encoder = new TextEncoder();
const carriers: readonly CarrierKind[] = Object.freeze(["raw_quic", "websocket", "webtransport"]);
const token = /^[a-z][a-z0-9_]{0,127}$/;
const identities = new Set([
  "go/native",
  "rust/native",
  "swift/ios",
  "swift/linux",
  "swift/macos",
  "typescript/browser",
  "typescript/node",
]);
const reasons = new Set([
  "adapter_not_composed",
  "browser_no_raw_udp",
  "browser_websocket_api_unavailable",
  "browser_webtransport_api_unavailable",
  "driver_unavailable",
  "node_native_transport_unavailable",
  "node_webtransport_driver_unavailable",
  "swift_apple_client_profile_excludes_raw_quic",
  "swift_apple_client_profile_excludes_webtransport",
  "websocket_adapter_not_supported_on_linux",
]);

export function defineRuntimeCapabilityDescriptorV3(
  runtime: "browser" | "node",
  tuples: readonly RuntimeCapabilityTupleV3[],
  unsupported: readonly UnsupportedRuntimeCarrierV3[],
): RuntimeCapabilityDescriptorV3 {
  const descriptor = freezeDescriptor({
    language: "typescript",
    runtime,
    schemaVersion: 3,
    tuples,
    unsupported,
  });
  validateRuntimeCapabilityDescriptorV3(descriptor);
  return descriptor;
}

export function encodeRuntimeCapabilityDescriptorV3(descriptor: RuntimeCapabilityDescriptorV3): string {
  validateRuntimeCapabilityDescriptorV3(descriptor);
  return canonicalizeJCSV3(descriptor as unknown as JCSValue);
}

export function decodeRuntimeCapabilityDescriptorV3(raw: string | Uint8Array): RuntimeCapabilityDescriptorV3 {
  let text: string;
  try {
    text = typeof raw === "string" ? raw : new TextDecoder("utf-8", { fatal: true }).decode(raw);
  } catch {
    throw new TypeError("runtime capability descriptor is not UTF-8");
  }
  let parsed: unknown;
  try {
    preflightJSONV3(text);
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new TypeError("invalid runtime capability JSON");
  }
  const descriptor = decodeDescriptor(parsed);
  if (encodeRuntimeCapabilityDescriptorV3(descriptor) !== text) {
    throw new TypeError("runtime capability descriptor is not canonical JCS");
  }
  return descriptor;
}

export function runtimeCapabilityDigestV3(descriptor: RuntimeCapabilityDescriptorV3): Uint8Array {
  const canonical = encoder.encode(encodeRuntimeCapabilityDescriptorV3(descriptor));
  return sha256(concatBytes([
    encoder.encode("flowersec-v3-runtime-capability\0"),
    u32be(canonical.length),
    canonical,
  ]));
}

export function runtimeCapabilityDigestHexV3(descriptor: RuntimeCapabilityDescriptorV3): string {
  return Array.from(runtimeCapabilityDigestV3(descriptor), (value) => value.toString(16).padStart(2, "0")).join("");
}

export function supportsCandidateSecurityV3(
  descriptor: RuntimeCapabilityDescriptorV3,
  carrier: CarrierKind,
  path: PathKind,
  sessionRole: SessionRoleV3,
  mode: TransportSecurityModeV3,
): boolean {
  validateRuntimeCapabilityDescriptorV3(descriptor);
  return descriptor.tuples.some((tuple) =>
    tuple.carrier === carrier && tuple.networkMode === "dial" && tuple.path === path &&
    tuple.sessionRole === sessionRole && tuple.securityModes.includes(mode));
}

export function validateRuntimeCapabilityDescriptorV3(descriptor: RuntimeCapabilityDescriptorV3): void {
  if (descriptor.schemaVersion !== 3 || !token.test(descriptor.language) || !token.test(descriptor.runtime) ||
      !identities.has(`${descriptor.language}/${descriptor.runtime}`)) {
    throw new TypeError("invalid runtime capability descriptor identity");
  }
  const supported = new Set<CarrierKind>();
  let previousTuple: RuntimeCapabilityTupleV3 | undefined;
  for (const tuple of descriptor.tuples) {
    validateTuple(tuple);
    if (previousTuple !== undefined && compareTuple(previousTuple, tuple) >= 0) {
      throw new TypeError("runtime capability tuples must be unique and canonically sorted");
    }
    supported.add(tuple.carrier);
    previousTuple = tuple;
  }
  const unavailable = new Set<CarrierKind>();
  let previousUnsupported: UnsupportedRuntimeCarrierV3 | undefined;
  for (const item of descriptor.unsupported) {
    if (!carriers.includes(item.carrier) || !reasons.has(item.reason) || supported.has(item.carrier)) {
      throw new TypeError("invalid unsupported runtime carrier");
    }
    if (previousUnsupported !== undefined && compareASCII(previousUnsupported.carrier, item.carrier) >= 0) {
      throw new TypeError("unsupported runtime carriers must be unique and canonically sorted");
    }
    unavailable.add(item.carrier);
    previousUnsupported = item;
  }
  for (const carrier of carriers) {
    if (supported.has(carrier) === unavailable.has(carrier)) {
      throw new TypeError(`runtime capability must support or explicitly reject ${carrier}`);
    }
  }
  validateRuntimeShape(descriptor);
}

function validateTuple(tuple: RuntimeCapabilityTupleV3): void {
  if (!carriers.includes(tuple.carrier) || !["dial", "listen"].includes(tuple.networkMode) ||
      !["direct", "tunnel"].includes(tuple.path) || !["client", "server"].includes(tuple.sessionRole) ||
      tuple.reliableStreams !== true || typeof tuple.datagrams !== "boolean" || typeof tuple.migration !== "boolean") {
    throw new TypeError("invalid runtime capability tuple");
  }
  const deployment = tuple.path === "direct"
    ? (tuple.networkMode === "dial" && tuple.sessionRole === "client") ||
      (tuple.networkMode === "listen" && tuple.sessionRole === "server")
    : tuple.networkMode === "dial";
  if (!deployment) throw new TypeError("invalid runtime capability deployment role");
  if (tuple.carrier === "websocket" && (tuple.datagrams || tuple.migration)) {
    throw new TypeError("WebSocket cannot advertise datagrams or migration");
  }
  const modes = tuple.securityModes;
  if (!Array.isArray(modes) || (tuple.networkMode === "listen"
    ? modes.length !== 0
    : !(equalStrings(modes, ["ca"]) || equalStrings(modes, ["pin"]) || equalStrings(modes, ["ca", "pin"])))) {
    throw new TypeError("invalid runtime capability security modes");
  }
}

function validateRuntimeShape(descriptor: RuntimeCapabilityDescriptorV3): void {
  const id = `${descriptor.language}/${descriptor.runtime}`;
  validateRegisteredTupleSets(descriptor, id);
  if (id === "typescript/browser") {
    validateReason(descriptor, "raw_quic", "browser_no_raw_udp");
    for (const tuple of descriptor.tuples) {
      if (tuple.carrier === "websocket" && !equalStrings(tuple.securityModes, ["ca"])) {
        throw new TypeError("browser WebSocket is CA-only");
      }
      if (tuple.carrier === "webtransport" &&
          !(equalStrings(tuple.securityModes, ["ca"]) || equalStrings(tuple.securityModes, ["ca", "pin"]))) {
        throw new TypeError("invalid browser WebTransport security modes");
      }
      if (tuple.networkMode !== "dial" || tuple.migration ||
          tuple.datagrams !== (tuple.carrier === "webtransport")) {
        throw new TypeError("invalid browser tuple");
      }
    }
  } else if (id === "typescript/node") {
    validateReason(descriptor, "webtransport", "node_webtransport_driver_unavailable");
    for (const tuple of descriptor.tuples) {
      if (!equalStrings(tuple.securityModes, tuple.networkMode === "listen" ? [] : ["ca", "pin"]) ||
          tuple.migration || tuple.datagrams !== (tuple.carrier === "raw_quic")) {
        throw new TypeError("invalid Node tuple");
      }
    }
  }
}

function validateRegisteredTupleSets(
  descriptor: RuntimeCapabilityDescriptorV3,
  id: string,
): void {
  const expected = registeredTupleSets(id);
  if (expected === undefined) throw new TypeError("invalid runtime capability identity");
  for (const carrier of carriers) {
    const actual = descriptor.tuples.filter((tuple) => tuple.carrier === carrier);
    const unsupported = descriptor.unsupported.find((entry) => entry.carrier === carrier);
    const carrierExpected = expected[carrier];
    if (unsupported !== undefined) {
      if (actual.length !== 0 || carrierExpected.unsupportedReasons?.includes(unsupported.reason) !== true) {
        throw new TypeError("runtime capability does not match its registered carrier set");
      }
      continue;
    }
    if (carrierExpected.tupleSets?.some((set) => equalTupleSets(actual, set)) !== true) {
      throw new TypeError("runtime capability does not match its registered tuple set");
    }
  }
}

type RegisteredCarrierSet = Readonly<{
  tupleSets?: readonly (readonly RuntimeCapabilityTupleV3[])[];
  unsupportedReasons?: readonly string[];
}>;

function registeredTupleSets(id: string): Readonly<Record<CarrierKind, RegisteredCarrierSet>> | undefined {
  const ca = ["ca"] as const;
  const caPin = ["ca", "pin"] as const;
  const websocket = (modes: readonly ("ca" | "pin")[]) => registeredTuples("websocket", false, false, true, modes);
  const websocket3 = (modes: readonly ("ca" | "pin")[]) => registeredTuples("websocket", false, false, false, modes);
  const rawQuic4M = registeredTuples("raw_quic", true, true, true, caPin);
  const rawQuic4N = registeredTuples("raw_quic", true, false, true, caPin);
  const webTransport4 = registeredTuples("webtransport", true, false, true, caPin);
  const webTransport3CA = registeredTuples("webtransport", true, false, false, ca);
  const webTransport3Pin = registeredTuples("webtransport", true, false, false, caPin);
  switch (id) {
    case "go/native":
      return {
        raw_quic: { tupleSets: [rawQuic4M], unsupportedReasons: ["adapter_not_composed"] },
        websocket: { tupleSets: [websocket(caPin)], unsupportedReasons: ["adapter_not_composed"] },
        webtransport: { tupleSets: [webTransport4], unsupportedReasons: ["adapter_not_composed"] },
      };
    case "typescript/browser":
      return {
        raw_quic: { unsupportedReasons: ["browser_no_raw_udp"] },
        websocket: { tupleSets: [websocket3(ca)], unsupportedReasons: ["browser_websocket_api_unavailable"] },
        webtransport: { tupleSets: [webTransport3CA, webTransport3Pin], unsupportedReasons: ["browser_webtransport_api_unavailable"] },
      };
    case "typescript/node":
      return {
        raw_quic: { tupleSets: [rawQuic4N], unsupportedReasons: ["node_native_transport_unavailable"] },
        websocket: { tupleSets: [websocket(caPin)] },
        webtransport: { unsupportedReasons: ["node_webtransport_driver_unavailable"] },
      };
    case "rust/native":
      return {
        raw_quic: { tupleSets: [rawQuic4M] },
        websocket: { tupleSets: [websocket(caPin)] },
        webtransport: { unsupportedReasons: ["driver_unavailable"] },
      };
    case "swift/ios":
    case "swift/macos":
      return {
        raw_quic: { unsupportedReasons: ["swift_apple_client_profile_excludes_raw_quic"] },
        websocket: { tupleSets: [websocket3(caPin)] },
        webtransport: { unsupportedReasons: ["swift_apple_client_profile_excludes_webtransport"] },
      };
    case "swift/linux":
      return {
        raw_quic: { unsupportedReasons: ["swift_apple_client_profile_excludes_raw_quic"] },
        websocket: { unsupportedReasons: ["websocket_adapter_not_supported_on_linux"] },
        webtransport: { unsupportedReasons: ["swift_apple_client_profile_excludes_webtransport"] },
      };
    default:
      return undefined;
  }
}

function registeredTuples(
  carrier: CarrierKind,
  datagrams: boolean,
  migration: boolean,
  includeListener: boolean,
  securityModes: readonly ("ca" | "pin")[],
): readonly RuntimeCapabilityTupleV3[] {
  const tuples: RuntimeCapabilityTupleV3[] = [
    { carrier, datagrams, migration, networkMode: "dial", path: "direct", reliableStreams: true, securityModes, sessionRole: "client" },
    { carrier, datagrams, migration, networkMode: "dial", path: "tunnel", reliableStreams: true, securityModes, sessionRole: "client" },
    { carrier, datagrams, migration, networkMode: "dial", path: "tunnel", reliableStreams: true, securityModes, sessionRole: "server" },
  ];
  if (includeListener) {
    tuples.push({ carrier, datagrams, migration: false, networkMode: "listen", path: "direct", reliableStreams: true, securityModes: [], sessionRole: "server" });
  }
  return tuples;
}

function equalTupleSets(
  actual: readonly RuntimeCapabilityTupleV3[],
  expected: readonly RuntimeCapabilityTupleV3[],
): boolean {
  return actual.length === expected.length && actual.every((tuple, index) => tupleKey(tuple) === tupleKey(expected[index]!));
}

function tupleKey(tuple: RuntimeCapabilityTupleV3): string {
  return JSON.stringify([
    tuple.carrier, tuple.networkMode, tuple.sessionRole, tuple.path,
    tuple.reliableStreams, tuple.datagrams, tuple.migration, [...tuple.securityModes],
  ]);
}

function validateReason(descriptor: RuntimeCapabilityDescriptorV3, carrier: CarrierKind, expected: string): void {
  const item = descriptor.unsupported.find((entry) => entry.carrier === carrier);
  if (item !== undefined && item.reason !== expected && !(
    carrier === "raw_quic" && descriptor.runtime === "browser" && item.reason === "browser_no_raw_udp"
  )) throw new TypeError("invalid unsupported reason for runtime");
}

function decodeDescriptor(input: unknown): RuntimeCapabilityDescriptorV3 {
  const object = exactObject(input, ["language", "runtime", "schemaVersion", "tuples", "unsupported"]);
  if (typeof object.language !== "string" || typeof object.runtime !== "string" || object.schemaVersion !== 3 ||
      !Array.isArray(object.tuples) || !Array.isArray(object.unsupported)) {
    throw new TypeError("invalid runtime capability descriptor");
  }
  const tuples = object.tuples.map((input): RuntimeCapabilityTupleV3 => {
    const value = exactObject(input, [
      "carrier", "datagrams", "migration", "networkMode", "path", "reliableStreams", "securityModes", "sessionRole",
    ]);
    if (typeof value.carrier !== "string" || typeof value.networkMode !== "string" ||
        typeof value.path !== "string" || typeof value.sessionRole !== "string" ||
        typeof value.datagrams !== "boolean" || typeof value.migration !== "boolean" ||
        value.reliableStreams !== true || !Array.isArray(value.securityModes) ||
        value.securityModes.some((mode) => mode !== "ca" && mode !== "pin")) {
      throw new TypeError("invalid runtime capability tuple");
    }
    return {
      carrier: value.carrier as CarrierKind,
      datagrams: value.datagrams,
      migration: value.migration,
      networkMode: value.networkMode as NetworkModeV3,
      path: value.path as PathKind,
      reliableStreams: true,
      securityModes: value.securityModes as TransportSecurityModeV3[],
      sessionRole: value.sessionRole as SessionRoleV3,
    };
  });
  const unsupported = object.unsupported.map((input): UnsupportedRuntimeCarrierV3 => {
    const value = exactObject(input, ["carrier", "reason"]);
    if (typeof value.carrier !== "string" || typeof value.reason !== "string") {
      throw new TypeError("invalid unsupported runtime carrier");
    }
    return { carrier: value.carrier as CarrierKind, reason: value.reason };
  });
  const descriptor = freezeDescriptor({
    language: object.language,
    runtime: object.runtime,
    schemaVersion: 3,
    tuples,
    unsupported,
  });
  validateRuntimeCapabilityDescriptorV3(descriptor);
  return descriptor;
}

function freezeDescriptor(descriptor: RuntimeCapabilityDescriptorV3): RuntimeCapabilityDescriptorV3 {
  return Object.freeze({
    ...descriptor,
    tuples: Object.freeze(descriptor.tuples.map((tuple) => Object.freeze({
      ...tuple,
      securityModes: Object.freeze([...tuple.securityModes]),
    }))),
    unsupported: Object.freeze(descriptor.unsupported.map((entry) => Object.freeze({ ...entry }))),
  });
}

function exactObject(input: unknown, keys: readonly string[]): Record<string, unknown> {
  if (typeof input !== "object" || input === null || Array.isArray(input)) throw new TypeError("expected object");
  const object = input as Record<string, unknown>;
  const actual = Object.keys(object).sort(compareASCII);
  const expected = [...keys].sort(compareASCII);
  if (!equalStrings(actual, expected)) throw new TypeError("object has unknown or missing fields");
  return object;
}

function compareTuple(left: RuntimeCapabilityTupleV3, right: RuntimeCapabilityTupleV3): number {
  return compareLists(
    [left.carrier, left.networkMode, left.sessionRole, left.path],
    [right.carrier, right.networkMode, right.sessionRole, right.path],
  );
}

function compareLists(left: readonly string[], right: readonly string[]): number {
  for (let index = 0; index < left.length; index += 1) {
    const order = compareASCII(left[index]!, right[index]!);
    if (order !== 0) return order;
  }
  return 0;
}

function compareASCII(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function equalStrings(left: readonly unknown[], right: readonly unknown[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}
