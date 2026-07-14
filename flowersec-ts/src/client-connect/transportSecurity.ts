import type { ClientPath } from "../client.js";
import { FlowersecError } from "../utils/errors.js";
import { emitObserverDiagnostic, type ClientObserverLike } from "../observability/observer.js";

export const RequireTLS = "require_tls" as const;
export const AllowPlaintextForLoopback = "allow_plaintext_for_loopback" as const;
export const AllowPlaintext = "allow_plaintext" as const;

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

function detectRuntime(): TransportSecurityPolicyInput["runtime"] {
  if (typeof window !== "undefined" && typeof window.document !== "undefined") return "browser";
  if (typeof process !== "undefined" && process.versions?.node != null) return "node";
  return "other";
}
