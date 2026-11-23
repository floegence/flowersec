import { normalizeCandidateURL, type ArtifactPathKindV3, type CanonicalArtifactCandidateV3 } from "./artifact.js";
import { ConnectErrorV3 } from "./security.js";

export function selectTunnelIngress(kind: ArtifactPathKindV3, candidates: readonly CanonicalArtifactCandidateV3[], url?: string) {
  if (url === undefined) {
    if (kind !== "tunnel" || new Set(candidates.map(candidate => candidate.normalized_url)).size === 1) return candidates;
  } else if (kind === "tunnel" && typeof url === "string" && url.length <= 2048) {
    const selected = candidates.filter(candidate => {
      try { return normalizeCandidateURL(kind, candidate.carrier, url) === candidate.normalized_url; }
      catch { return false; }
    });
    if (selected.length) return selected;
  }
  throw new ConnectErrorV3("tunnel_ingress_mismatch", { kind: "terminal" });
}
