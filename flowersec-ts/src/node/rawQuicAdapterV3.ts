import { rootCertificates } from "node:tls";

import type { ArtifactV3, CanonicalArtifactCandidateV3 } from "../v3/artifact.js";
import type { NativeCarrierSessionV3 } from "../v3/carrier.js";
import {
  snapshotTransportSecurityPolicyV3,
  TransportFailureV3,
} from "../v3/security.js";
import type {
  NativeRawQuicConnectOptions,
  NativeRawQuicDriver,
} from "./nativeTransportAddon.js";
import { normalizeCertificateChain } from "./rawQuicTls.js";
import { alpnForPathV3 } from "../v3/transportConstants.js";

const DEFAULT_HANDSHAKE_TIMEOUT_MS = 10_000;
type NodeTLSRootsV3 = string | Uint8Array | readonly (string | Uint8Array)[];

export async function createNodeRawQuicClientV3(
  driver: NativeRawQuicDriver,
  candidate: CanonicalArtifactCandidateV3,
  artifact: ArtifactV3,
  attemptNowUnixSeconds: number,
  options: Readonly<{
    roots?: NodeTLSRootsV3;
    signal?: AbortSignal;
    handshakeTimeoutMs?: number;
  }> = {},
): Promise<NativeCarrierSessionV3> {
  if (candidate.carrier !== "raw_quic") throw new TransportFailureV3("invalid_artifact");
  if (candidate.wire_profile !== alpnForPathV3(artifact.path.kind)) {
    throw new TransportFailureV3("invalid_artifact");
  }
  let url: URL;
  try {
    url = new URL(candidate.normalized_url);
  } catch {
    throw new TransportFailureV3("invalid_artifact");
  }
  if (url.protocol !== "quic:" || url.pathname !== "" || url.search !== "" || url.hash !== "" ||
      url.username !== "" || url.password !== "") {
    throw new TransportFailureV3("invalid_artifact");
  }
  const handshakeTimeoutMs = options.handshakeTimeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS;
  if (!Number.isSafeInteger(handshakeTimeoutMs) || handshakeTimeoutMs < 1 || handshakeTimeoutMs > 120_000) {
    throw new TransportFailureV3("invalid_artifact");
  }
  const policy = snapshotTransportSecurityPolicyV3(
    candidate.tls,
    attemptNowUnixSeconds,
    ["ca", "pin"],
  );
  const common = {
    host: unbracket(url.hostname),
    port: url.port === "" ? 443 : Number(url.port),
    serverName: unbracket(url.hostname),
    path: artifact.path.kind,
    inboundBidirectionalStreamCapacity: artifact.session.max_inbound_streams + 2,
    handshakeTimeoutMs,
  } as const;
  const nativeOptions: NativeRawQuicConnectOptions = policy.mode === "ca"
    ? {
        ...common,
        tlsMode: "ca",
        trustRootsDer: normalizeCertificateChain(options.roots ?? rootCertificates),
      }
    : {
        ...common,
        tlsMode: "pin",
        activeLeafDerSha256: policy.activeLeafDerSHA256,
      };
  try {
    return await driver.connectRawQuic(nativeOptions, {
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
  } catch (error) {
    if (error instanceof TransportFailureV3) throw error;
    if (options.signal?.aborted === true) throw options.signal.reason;
    const reason = error instanceof Error ? error.message : "";
    switch (reason) {
      case "pin_mismatch":
        throw new TransportFailureV3("tls_failed", "pin_mismatch", error);
      case "pin_certificate_invalid":
      case "handshake_failed":
      case "invalid_alpn":
        throw new TransportFailureV3("tls_failed", "unknown", error);
      case "invalid_tls_policy":
      case "invalid_trust_roots":
      case "invalid_limits":
        throw new TransportFailureV3("invalid_artifact", undefined, error);
      default:
        throw new TransportFailureV3("connection_failed", undefined, error);
    }
  }
}

function unbracket(host: string): string {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}
