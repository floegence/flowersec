import type { ClientPath } from "../client.js";
import { FlowersecError } from "../utils/errors.js";
import { emitObserverDiagnostic, type ClientObserverLike } from "../observability/observer.js";

export const RequireTLS = "require_tls" as const;
export const AllowPlaintextForLoopback = "allow_plaintext_for_loopback" as const;
/** @deprecated Use RequireTLS, AllowPlaintextForLoopback, or createNetworkPlaintextPolicy. */
export const AllowPlaintext = "allow_plaintext" as const;

export const PlaintextRiskAcceptance = {
  acceptPreE2ECredentialExposure: "accept_pre_e2ee_credential_exposure",
} as const;

export type PlaintextRiskAcceptance = typeof PlaintextRiskAcceptance[keyof typeof PlaintextRiskAcceptance];

export type NetworkPlaintextPolicyOptions = Readonly<{
  allowedHosts: readonly string[];
  riskAcceptance: PlaintextRiskAcceptance;
}>;

export type TransportSecurityPolicyInput = Readonly<{
  path: ClientPath;
  scheme: "ws" | "wss";
  host: string;
  runtime: "browser" | "node" | "other";
}>;

export type TransportSecurityPolicyPreset =
  | typeof RequireTLS
  | typeof AllowPlaintextForLoopback
  | typeof AllowPlaintext;

export type TransportSecurityPolicy =
  | TransportSecurityPolicyPreset
  | ((input: TransportSecurityPolicyInput) => boolean | Promise<boolean>);

export function createNetworkPlaintextPolicy(options: NetworkPlaintextPolicyOptions): TransportSecurityPolicy {
  if (options?.riskAcceptance !== PlaintextRiskAcceptance.acceptPreE2ECredentialExposure) {
    throw new Error("network plaintext policy requires explicit pre-E2EE credential exposure acceptance");
  }
  if (!Array.isArray(options.allowedHosts) || options.allowedHosts.length === 0) {
    throw new Error("network plaintext policy requires at least one allowed host");
  }
  const allowedHosts = new Set(options.allowedHosts.map(canonicalNetworkPlaintextHost));
  return (input) => input.scheme === "wss" || (input.scheme === "ws" && allowedHosts.has(input.host));
}

type ParsedWebSocketTarget = Readonly<{
  scheme: "ws" | "wss";
  host: string;
}>;

export async function enforceTransportSecurity(args: Readonly<{
  rawUrl: string;
  path: ClientPath;
  policy?: TransportSecurityPolicy;
  observer?: ClientObserverLike;
}>): Promise<void> {
  let target: ParsedWebSocketTarget;
  try {
    target = parseWebSocketTarget(args.rawUrl);
  } catch (cause) {
    throw denied(args.path, cause);
  }
  const input: TransportSecurityPolicyInput = {
    path: args.path,
    scheme: target.scheme,
    host: target.host,
    runtime: detectRuntime(),
  };

  let allowed = false;
  const policy = args.policy ?? RequireTLS;
  try {
    if (typeof policy === "function") {
      allowed = await policy(input);
    } else {
      allowed = evaluatePreset(policy, target);
    }
  } catch (cause) {
    throw denied(args.path, cause);
  }
  if (!allowed) throw denied(args.path);
  if (target.scheme === "ws") {
    emitObserverDiagnostic(args.observer, {
      path: args.path,
      stage: "transport",
      code_domain: "event",
      code: "plaintext_transport",
      result: "skip",
    });
  }
}

function denied(path: ClientPath, cause?: unknown): FlowersecError {
  return new FlowersecError({
    path,
    stage: "validate",
    code: "transport_policy_denied",
    message: "transport security policy denied websocket URL",
    ...(cause === undefined ? {} : { cause }),
  });
}

function evaluatePreset(policy: TransportSecurityPolicyPreset, target: ParsedWebSocketTarget): boolean {
  switch (policy) {
    case RequireTLS:
      return target.scheme === "wss";
    case AllowPlaintextForLoopback:
      return target.scheme === "wss" || isLiteralLoopbackHost(target.host);
    case AllowPlaintext:
      return true;
  }
}

function parseWebSocketTarget(rawUrl: string): ParsedWebSocketTarget {
  const raw = rawUrl.trim();
  const match = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)(?:[/?#]|$)/.exec(raw);
  const scheme = match?.[1]?.toLowerCase();
  const authority = match?.[2] ?? "";
  if ((scheme !== "ws" && scheme !== "wss") || authority === "" || authority.includes("@")) {
    throw new Error("invalid websocket URL");
  }

  let host: string;
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    if (end <= 1 || (authority.slice(end + 1) !== "" && !/^:\d+$/.test(authority.slice(end + 1)))) {
      throw new Error("invalid websocket URL");
    }
    host = authority.slice(1, end).toLowerCase();
  } else {
    const pieces = authority.split(":");
    if (pieces.length > 2 || (pieces.length === 2 && !/^\d+$/.test(pieces[1] ?? ""))) {
      throw new Error("invalid websocket URL");
    }
    host = (pieces[0] ?? "").toLowerCase();
  }
  if (host === "") throw new Error("invalid websocket URL");
  return { scheme, host };
}

function isLiteralLoopbackHost(host: string): boolean {
  if (host === "localhost" || host === "::1") return true;
  const parts = host.split(".");
  if (parts.length !== 4) return false;
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) return false;
    const value = Number(part);
    if (value > 255) return false;
    octets.push(value);
  }
  return octets[0] === 127;
}

function canonicalNetworkPlaintextHost(rawHost: string): string {
  const host = String(rawHost ?? "").trim();
  if (host === "" || host !== host.toLowerCase() || /[@/?#%\[\]]/.test(host)) {
    throw new Error(`invalid network plaintext allowed host ${JSON.stringify(rawHost)}`);
  }
  if (host.includes(":")) {
    return canonicalNetworkIPv6Host(host);
  }
  const octets = canonicalIPv4Octets(host);
  const firstOctet = octets[0];
  const secondOctet = octets[1];
  if (firstOctet == null || secondOctet == null) {
    throw new Error(`network plaintext allowed host must be a canonical IP literal: ${JSON.stringify(rawHost)}`);
  }
  if (firstOctet === 127 || (firstOctet === 169 && secondOctet === 254) || firstOctet >= 224 || octets.every((value) => value === 0)) {
    throw new Error(`network plaintext allowed host must be a non-loopback unicast IP literal: ${JSON.stringify(rawHost)}`);
  }
  return host;
}

function canonicalIPv4Octets(host: string): readonly number[] {
  const parts = host.split(".");
  if (parts.length !== 4) {
    throw new Error(`network plaintext allowed host must be a canonical IP literal: ${JSON.stringify(host)}`);
  }
  const octets = parts.map((part) => {
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) {
      throw new Error(`network plaintext allowed host must be a canonical IP literal: ${JSON.stringify(host)}`);
    }
    const value = Number(part);
    if (value > 255) {
      throw new Error(`network plaintext allowed host must be a canonical IP literal: ${JSON.stringify(host)}`);
    }
    return value;
  });
  return octets;
}

function canonicalNetworkIPv6Host(host: string): string {
  let parsed: URL;
  try {
    parsed = new URL(`http://[${host}]/`);
  } catch {
    throw new Error(`network plaintext allowed host must be a canonical IP literal: ${JSON.stringify(host)}`);
  }
  const canonical = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (canonical !== host) {
    throw new Error(`network plaintext allowed host must be a canonical IP literal: ${JSON.stringify(host)}`);
  }
  const words = expandIPv6Words(canonical);
  const unspecified = words.every((word) => word === 0);
  const loopback = words.slice(0, 7).every((word) => word === 0) && words[7] === 1;
  const mappedIPv4 = words.slice(0, 5).every((word) => word === 0) && words[5] === 0xffff;
  const multicast = (words[0]! & 0xff00) === 0xff00;
  const linkLocal = (words[0]! & 0xffc0) === 0xfe80;
  if (unspecified || loopback || mappedIPv4 || multicast || linkLocal) {
    throw new Error(`network plaintext allowed host must be a non-loopback unicast IP literal: ${JSON.stringify(host)}`);
  }
  return canonical;
}

function expandIPv6Words(host: string): readonly number[] {
  const halves = host.split("::");
  if (halves.length > 2) throw new Error("invalid IPv6 host");
  const left = halves[0] === "" ? [] : halves[0]!.split(":");
  const right = halves.length === 1 || halves[1] === "" ? [] : halves[1]!.split(":");
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) {
    throw new Error("invalid IPv6 host");
  }
  const words = [...left, ...Array.from({ length: missing }, () => "0"), ...right].map((part) => Number.parseInt(part, 16));
  if (words.length !== 8 || words.some((word) => !Number.isInteger(word) || word < 0 || word > 0xffff)) {
    throw new Error("invalid IPv6 host");
  }
  return words;
}

function detectRuntime(): TransportSecurityPolicyInput["runtime"] {
  if (typeof window !== "undefined" && typeof window.document !== "undefined") return "browser";
  if (typeof process !== "undefined" && process.versions?.node != null) return "node";
  return "other";
}
