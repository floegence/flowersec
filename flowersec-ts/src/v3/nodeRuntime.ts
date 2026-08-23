import { X509Certificate, constants, createHash, timingSafeEqual } from "node:crypto";
import { createRequire } from "node:module";
import {
  checkServerIdentity as tlsCheckServerIdentity,
  connect as tlsConnect,
  type ConnectionOptions,
  type TLSSocket,
} from "node:tls";

import type { WebSocketLike } from "../ws-client/binaryTransport.js";
import type { CanonicalArtifactCandidateV3 } from "./artifact.js";
import { defineRuntimeCapabilityDescriptorV3, type RuntimeCapabilityTupleV3 } from "./capability.js";
import { snapshotTransportSecurityPolicyV3, TransportFailureV3, type TransportSecuritySnapshotV3 } from "./security.js";
import {
  FLOWERSEC_V3_PATHS,
  FLOWERSEC_V3_WIRE_PROFILES,
  websocketSubprotocolForPathV3,
} from "./transportConstants.js";

const websocketTuples = tuplesFor("websocket", false);
const rawQuicTuples = tuplesFor("raw_quic", true);

export const NODE_RUNTIME_CAPABILITY_V3 = defineRuntimeCapabilityDescriptorV3(
  "node",
  websocketTuples,
  [
    { carrier: "raw_quic", reason: "node_native_transport_unavailable" },
    { carrier: "webtransport", reason: "node_webtransport_driver_unavailable" },
  ],
);

const NODE_RUNTIME_WITH_NATIVE_CAPABILITY_V3 = defineRuntimeCapabilityDescriptorV3(
  "node",
  [...rawQuicTuples, ...websocketTuples],
  [{ carrier: "webtransport", reason: "node_webtransport_driver_unavailable" }],
);

export function detectNodeRuntimeCapabilityV3(
  nativeTransportAvailable = false,
  _webSocketOriginAvailable = true,
) {
  return nativeTransportAvailable ? NODE_RUNTIME_WITH_NATIVE_CAPABILITY_V3 : NODE_RUNTIME_CAPABILITY_V3;
}

export type NodeTLSRootsV3 = string | Uint8Array | readonly (string | Uint8Array)[];

export type NodeWebSocketV3 = WebSocketLike & Readonly<{ protocol?: string }>;

export async function connectNodeTLSSocketV3(
  candidate: CanonicalArtifactCandidateV3,
  attemptNowUnixSeconds: number,
  options: Readonly<{
    roots?: NodeTLSRootsV3;
    signal?: AbortSignal;
    timeoutMilliseconds?: number;
    nowUnixMilliseconds?: () => number;
  }> = {},
): Promise<TLSSocket> {
  if (candidate.carrier !== "websocket") throw new TransportFailureV3("invalid_artifact");
  const url = new URL(candidate.normalized_url);
  if (url.href !== candidate.normalized_url || url.protocol !== "wss:" ||
      url.pathname !== pathFromProfile(candidate.wire_profile) || url.username !== "" || url.password !== "" ||
      url.search !== "" || url.hash !== "") throw new TransportFailureV3("invalid_artifact");
  const policy = snapshotTransportSecurityPolicyV3(candidate.tls, attemptNowUnixSeconds, ["ca", "pin"]);
  const port = url.port === "" ? 443 : Number(url.port);
  const host = unbracket(url.hostname);
  const tlsOptions: ConnectionOptions = {
    host,
    port,
    minVersion: "TLSv1.3",
    maxVersion: "TLSv1.3",
    ALPNProtocols: ["http/1.1"],
    secureOptions: constants.SSL_OP_NO_TICKET,
    rejectUnauthorized: policy.mode === "ca",
    ...(isIPAddress(host)
      ? { checkServerIdentity: (_servername: string, certificate: Parameters<typeof tlsCheckServerIdentity>[1]) =>
        tlsCheckServerIdentity(host, certificate) }
      : { servername: host }),
    ...(policy.mode === "ca" && options.roots !== undefined ? { ca: options.roots as ConnectionOptions["ca"] } : {}),
  };
  const timeout = options.timeoutMilliseconds ?? 10_000;
  if (!Number.isSafeInteger(timeout) || timeout < 1) {
    throw new TransportFailureV3("invalid_artifact");
  }
  const socket = tlsConnect(tlsOptions);
  return await new Promise<TLSSocket>((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => fail(new TransportFailureV3("connection_failed")), timeout);
    const abort = () => fail(options.signal?.reason ?? new Error("aborted"));
    const cleanup = () => {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", abort);
      socket.removeListener("error", onError);
    };
    const fail = (error: unknown) => {
      if (settled) return;
      settled = true;
      cleanup();
      socket.destroy();
      reject(error);
    };
    const onError = (error: Error & { code?: string }) => {
      if (policy.mode === "ca" && isNodeCertificateTrustErrorV3(error.code)) {
        fail(new TransportFailureV3("tls_failed", "ca_untrusted", error));
      } else if (policy.mode === "pin" && isTLSProtocolError(error.code)) {
        fail(new TransportFailureV3("tls_failed", "unknown", error));
      } else {
        fail(new TransportFailureV3("connection_failed", undefined, error));
      }
    };
    socket.once("error", onError);
    socket.once("secureConnect", () => {
      if (settled) return;
      try {
        if (policy.mode === "pin") {
          const peer = socket.getPeerX509Certificate();
          if (peer === undefined) throw new TransportFailureV3("tls_failed", "unknown");
          verifyPinnedLeafCertificateV3(peer.raw, policy, (options.nowUnixMilliseconds ?? Date.now)());
        }
      } catch (error) {
        fail(error instanceof TransportFailureV3 ? error : new TransportFailureV3("tls_failed", "unknown", error));
        return;
      }
      settled = true;
      cleanup();
      resolve(socket);
    });
    if (options.signal?.aborted === true) abort();
    else options.signal?.addEventListener("abort", abort, { once: true });
  });
}

export async function connectNodeWebSocketV3(
  candidate: CanonicalArtifactCandidateV3,
  attemptNowUnixSeconds: number,
  options: Readonly<{
    origin: string;
    roots?: NodeTLSRootsV3;
    signal?: AbortSignal;
    timeoutMilliseconds?: number;
    maxPayload?: number;
  }>,
): Promise<NodeWebSocketV3> {
  const origin = validateOrigin(options.origin);
  const maxPayload = options.maxPayload ?? 1_048_576;
  if (!Number.isSafeInteger(maxPayload) || maxPayload < 1) {
    throw new TransportFailureV3("invalid_artifact");
  }
  const socket = await connectNodeTLSSocketV3(candidate, attemptNowUnixSeconds, {
    ...(options.roots === undefined ? {} : { roots: options.roots }),
    ...(options.signal === undefined ? {} : { signal: options.signal }),
    ...(options.timeoutMilliseconds === undefined ? {} : { timeoutMilliseconds: options.timeoutMilliseconds }),
  });
  if (options.signal?.aborted === true) {
    socket.destroy();
    throw options.signal.reason;
  }
  const require = createRequire(import.meta.url);
  const wsModule = require("ws") as { WebSocket?: new (...args: unknown[]) => NodeWebSocketV3 } |
    (new (...args: unknown[]) => NodeWebSocketV3);
  const Constructor = typeof wsModule === "function" ? wsModule : wsModule.WebSocket;
  if (Constructor === undefined) {
    socket.destroy();
    throw new TransportFailureV3("tls_unsupported");
  }
  const subprotocol = candidate.wire_profile === FLOWERSEC_V3_WIRE_PROFILES.direct
    ? websocketSubprotocolForPathV3("direct")
    : candidate.wire_profile === FLOWERSEC_V3_WIRE_PROFILES.tunnel
      ? websocketSubprotocolForPathV3("tunnel")
      : invalidProfile();
  let webSocket: NodeWebSocketV3;
  try {
    webSocket = new Constructor(candidate.normalized_url, [subprotocol], {
      createConnection: () => socket,
      followRedirects: false,
      headers: { Origin: origin },
      maxPayload,
      perMessageDeflate: false,
    });
  } catch (error) {
    socket.destroy();
    throw new TransportFailureV3("connection_failed", undefined, error);
  }
  try {
    await waitForWebSocketOpen(webSocket, subprotocol, options.signal);
    return webSocket;
  } catch (error) {
    try { webSocket.close(); } catch { /* best effort */ }
    socket.destroy();
    throw error instanceof TransportFailureV3
      ? error
      : new TransportFailureV3("connection_failed", undefined, error);
  }
}

export function verifyPinnedLeafCertificateV3(
  leafDER: Uint8Array,
  policy: Extract<TransportSecuritySnapshotV3, { mode: "pin" }>,
  nowUnixMilliseconds: number,
): void {
  if (!Number.isSafeInteger(nowUnixMilliseconds) || nowUnixMilliseconds < 0) {
    throw new TransportFailureV3("tls_failed", "unknown");
  }
  let certificate: X509Certificate;
  try {
    certificate = new X509Certificate(leafDER);
    const notBefore = Date.parse(certificate.validFrom);
    const notAfter = Date.parse(certificate.validTo);
    const details = certificate.publicKey.asymmetricKeyDetails;
    if (!isX509V3CertificateDER(certificate.raw) ||
        !Number.isFinite(notBefore) || !Number.isFinite(notAfter) || nowUnixMilliseconds < notBefore ||
        nowUnixMilliseconds >= notAfter || notAfter - notBefore > 1_209_600_000 ||
        certificate.publicKey.asymmetricKeyType !== "ec" || details?.namedCurve !== "prime256v1") {
      throw new Error("certificate profile");
    }
  } catch (error) {
    throw new TransportFailureV3("tls_failed", "unknown", error);
  }
  const digest = createHash("sha256").update(certificate.raw).digest();
  let matched = 0;
  for (const pin of policy.activeLeafDerSHA256) {
    if (pin.length === digest.length && timingSafeEqual(pin, digest)) matched |= 1;
  }
  if (matched === 0) {
    throw new TransportFailureV3("tls_failed", "pin_mismatch");
  }
}

function isX509V3CertificateDER(der: Uint8Array): boolean {
  const certificate = readDERElement(der, 0, 0x30);
  if (certificate === undefined || certificate.next !== der.length) return false;
  const tbsCertificate = readDERElement(certificate.value, 0, 0x30);
  if (tbsCertificate === undefined) return false;
  const explicitVersion = readDERElement(tbsCertificate.value, 0, 0xa0);
  if (explicitVersion === undefined) return false;
  const version = readDERElement(explicitVersion.value, 0, 0x02);
  return version !== undefined && version.next === explicitVersion.value.length &&
    version.value.length === 1 && version.value[0] === 2;
}

function readDERElement(
  bytes: Uint8Array,
  offset: number,
  expectedTag: number,
): Readonly<{ value: Uint8Array; next: number }> | undefined {
  if (offset >= bytes.length || bytes[offset] !== expectedTag) return undefined;
  let cursor = offset + 1;
  if (cursor >= bytes.length) return undefined;
  const firstLength = bytes[cursor++] ?? 0;
  let length = firstLength;
  if ((firstLength & 0x80) !== 0) {
    const count = firstLength & 0x7f;
    if (count === 0 || count > 4 || cursor + count > bytes.length) return undefined;
    length = 0;
    for (let index = 0; index < count; index += 1) {
      length = length * 256 + (bytes[cursor++] ?? 0);
    }
  }
  if (cursor + length > bytes.length) return undefined;
  return { value: bytes.subarray(cursor, cursor + length), next: cursor + length };
}

function tuplesFor(carrier: "websocket" | "raw_quic", datagrams: boolean): readonly RuntimeCapabilityTupleV3[] {
  return Object.freeze([
    { carrier, datagrams, migration: false, networkMode: "dial", path: "direct", reliableStreams: true, securityModes: ["ca", "pin"], sessionRole: "client" },
    { carrier, datagrams, migration: false, networkMode: "dial", path: "tunnel", reliableStreams: true, securityModes: ["ca", "pin"], sessionRole: "client" },
    { carrier, datagrams, migration: false, networkMode: "dial", path: "tunnel", reliableStreams: true, securityModes: ["ca", "pin"], sessionRole: "server" },
    { carrier, datagrams, migration: false, networkMode: "listen", path: "direct", reliableStreams: true, securityModes: [], sessionRole: "server" },
  ]);
}

function pathFromProfile(profile: string): string {
  if (profile === FLOWERSEC_V3_WIRE_PROFILES.direct) return FLOWERSEC_V3_PATHS.websocket.direct;
  if (profile === FLOWERSEC_V3_WIRE_PROFILES.tunnel) return FLOWERSEC_V3_PATHS.websocket.tunnel;
  throw new TransportFailureV3("invalid_artifact");
}

function unbracket(host: string): string {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

function isIPAddress(host: string): boolean {
  return /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(":");
}

export function isNodeCertificateTrustErrorV3(code: string | undefined): boolean {
  return code !== undefined && NODE_CERTIFICATE_TRUST_ERROR_CODES.has(code);
}

const NODE_CERTIFICATE_TRUST_ERROR_CODES = new Set([
  "CERT_HAS_EXPIRED",
  "CERT_NOT_YET_VALID",
  "CERT_REJECTED",
  "CERT_REVOKED",
  "CERT_SIGNATURE_FAILURE",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "ERR_TLS_CERT_ALTNAME_INVALID",
  "INVALID_CA",
  "INVALID_PURPOSE",
  "PATH_LENGTH_EXCEEDED",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_DECRYPT_CERT_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
]);

function isTLSProtocolError(code: string | undefined): boolean {
  return code?.startsWith("ERR_SSL_") === true || code?.startsWith("ERR_TLS_") === true;
}

function validateOrigin(raw: string): string {
  let value: URL;
  try { value = new URL(raw); } catch { throw new TransportFailureV3("invalid_artifact"); }
  if ((value.protocol !== "https:" && value.protocol !== "http:") || value.origin !== raw ||
      value.username !== "" || value.password !== "") throw new TransportFailureV3("invalid_artifact");
  return value.origin;
}

function invalidProfile(): never {
  throw new TransportFailureV3("invalid_artifact");
}

async function waitForWebSocketOpen(
  socket: NodeWebSocketV3,
  expectedProtocol: string,
  signal?: AbortSignal,
): Promise<void> {
  if (socket.readyState === 1) {
    if (socket.protocol !== expectedProtocol) throw new TransportFailureV3("connection_failed");
    return;
  }
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const cleanup = () => {
      socket.removeEventListener("open", open);
      socket.removeEventListener("error", error);
      socket.removeEventListener("close", close);
      signal?.removeEventListener("abort", abort);
    };
    const finish = (failure?: unknown) => {
      if (settled) return;
      settled = true;
      cleanup();
      failure === undefined ? resolve() : reject(failure);
    };
    const open = () => socket.protocol === expectedProtocol
      ? finish()
      : finish(new TransportFailureV3("connection_failed"));
    const error = (event: unknown) => finish(new TransportFailureV3("connection_failed", undefined, event));
    const close = () => finish(new TransportFailureV3("connection_failed"));
    const abort = () => finish(signal?.reason);
    socket.addEventListener("open", open);
    socket.addEventListener("error", error);
    socket.addEventListener("close", close);
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted === true) abort();
  });
}
