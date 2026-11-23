import type { X509Certificate } from "node:crypto";
import { isIP } from "node:net";
import { normalizeCandidateURL, type CanonicalArtifactCandidateV3 } from "../v3/artifact.js";
import { snapshotTransportSecurityPolicyV3 } from "../v3/security.js";
import { verifyPinnedLeafCertificateV3 } from "../v3/nodeRuntime.js";
import { FLOWERSEC_V3_PATHS } from "../v3/transportConstants.js";

export type BoundIngress = Readonly<{ url: string; leaf: X509Certificate }>;

export function matchesIngress(candidate: CanonicalArtifactCandidateV3 | undefined, ingress: BoundIngress, now = Date.now()): boolean {
  if (candidate?.normalized_url !== ingress.url) return false;
  try {
    const policy = snapshotTransportSecurityPolicyV3(candidate.tls, Math.floor(now / 1000), ["ca", "pin"]);
    if (policy.mode === "pin") {
      verifyPinnedLeafCertificateV3(ingress.leaf.raw, policy, now);
      return true;
    }
    const host = new URL(ingress.url).hostname.replace(/^\[|\]$/gu, "");
    const leaf = ingress.leaf;
    return now >= leaf.validFromDate.getTime() && now < leaf.validToDate.getTime() &&
      (isIP(host) ? leaf.checkIP(host) : leaf.checkHost(host, { subject: "never", partialWildcards: false })) !== undefined;
  } catch { return false; }
}

/** A trusted deployment may map a forwarded public URL to one physical listener. */
export function boundIngressURL(path: "direct" | "tunnel", carrier: "websocket" | "raw_quic" | "webtransport",
  address: Readonly<{ host: string; port: number }>, publicURL?: string): string {
  if (publicURL !== undefined) return normalizeCandidateURL(path, carrier, publicURL);
  if (address.host === "::" || address.host === "0.0.0.0") throw new TypeError("publicURL is required for a wildcard listener");
  const host = address.host.includes(":") ? `[${address.host}]` : address.host;
  const url = carrier === "raw_quic" ? `quic://${host}:${address.port}` : `${carrier === "websocket" ? "wss" : "https"}://${host}:${address.port}${FLOWERSEC_V3_PATHS[carrier][path]}`;
  return normalizeCandidateURL(path, carrier, url);
}
