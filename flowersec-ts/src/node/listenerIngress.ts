import { normalizeCandidateURL } from "../v3/artifact.js";
import { FLOWERSEC_V3_PATHS } from "../v3/transportConstants.js";

/** A trusted deployment may map a forwarded public URL to one physical listener. */
export function boundIngressURL(path: "direct" | "tunnel", carrier: "websocket" | "raw_quic" | "webtransport",
  address: Readonly<{ host: string; port: number }>, publicURL?: string): string {
  if (publicURL !== undefined) return normalizeCandidateURL(path, carrier, publicURL);
  if (address.host === "::" || address.host === "0.0.0.0") throw new TypeError("publicURL is required for a wildcard listener");
  const host = address.host.includes(":") ? `[${address.host}]` : address.host;
  const url = carrier === "raw_quic" ? `quic://${host}:${address.port}` : `${carrier === "websocket" ? "wss" : "https"}://${host}:${address.port}${FLOWERSEC_V3_PATHS[carrier][path]}`;
  return normalizeCandidateURL(path, carrier, url);
}
