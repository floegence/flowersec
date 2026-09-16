import { base64urlDecode, base64urlEncode } from "../utils/base64url.js";
import { canonicalizeJCSV3, type JCSValue } from "../v3/jcs.js";
import { preflightJSONV3 } from "../v3/jsonPreflight.js";
import { decodeArtifactV3JSON, type ArtifactV3 } from "../v3/artifact.js";
import { createArtifactLeaseV3Internal, type ArtifactLeaseV3 } from "../v3/artifactLease.js";

// Each profile gets distinct opaque handles and lease storage. Only bounded
// decoding and v3 binding validation are shared, never admission authority.
export function createDirectWebSocketProfileV1<Artifact extends object, Lease extends object>(options: Readonly<{
  profile: string;
  candidateID: string;
  validateEndpoint: (raw: string) => string;
  error: () => Error;
}>) {
  type State = Readonly<{ endpoint: string; innerArtifact: ArtifactV3 }>;
  const artifacts = new WeakMap<Artifact, State>();
  const leases = new WeakMap<Lease, State & { innerLease: ArtifactLeaseV3 }>();
  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  return {
    parse(input: string | Uint8Array): Artifact {
      try {
        const bytes = typeof input === "string" ? encoder.encode(input) : input;
        if (bytes.length === 0 || bytes.length > 100_000) throw options.error();
        const text = decoder.decode(bytes);
        if (encoder.encode(text).length !== bytes.length) throw options.error();
        preflightJSONV3(text);
        const value = JSON.parse(text) as unknown;
        if (value === null || typeof value !== "object" || Array.isArray(value)) throw options.error();
        const wire = value as Record<string, unknown>;
        const keys = Object.keys(wire).sort();
        const expected = ["artifact_b64u", "endpoint", "profile", "v"];
        if (keys.length !== expected.length || !keys.every((key, index) => key === expected[index]) ||
            wire.v !== 1 || wire.profile !== options.profile || typeof wire.artifact_b64u !== "string" ||
            typeof wire.endpoint !== "string" || canonicalizeJCSV3(value as JCSValue) !== text) throw options.error();
        const innerBytes = base64urlDecode(wire.artifact_b64u);
        if (innerBytes.length === 0 || innerBytes.length > 65_536 || base64urlEncode(innerBytes) !== wire.artifact_b64u) throw options.error();
        const endpoint = options.validateEndpoint(wire.endpoint);
        const innerArtifact = decodeArtifactV3JSON(innerBytes);
        if (innerArtifact.path.kind !== "direct" || innerArtifact.path.candidates.length !== 1) throw options.error();
        const candidate = innerArtifact.path.candidates[0]!;
        const binding = new URL(endpoint);
        const port = binding.port || "80";
        binding.protocol = "wss:";
        binding.port = port;
        if (candidate.id !== options.candidateID || candidate.carrier !== "websocket" || candidate.tls.mode !== "ca" ||
            candidate.wire_profile !== "flowersec-direct/3" || candidate.normalized_url !== binding.href || candidate.url !== binding.href) throw options.error();
        const handle = Object.freeze({}) as Artifact;
        artifacts.set(handle, Object.freeze({endpoint, innerArtifact}));
        return handle;
      } catch { throw options.error(); }
    },
    createLease(artifact: Artifact, commitSpend: (signal?: AbortSignal) => Promise<void>, retireCleanup?: () => Promise<void>): Lease {
      const state = artifacts.get(artifact);
      if (state === undefined) throw options.error();
      const handle = Object.freeze({}) as Lease;
      leases.set(handle, {...state, innerLease: createArtifactLeaseV3Internal(state.innerArtifact, commitSpend, retireCleanup)});
      return handle;
    },
    unwrap(lease: Lease): Readonly<{endpoint: string; innerLease: ArtifactLeaseV3}> {
      const state = leases.get(lease);
      if (state === undefined) throw options.error();
      return state;
    },
  };
}
