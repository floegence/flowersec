import { readFileSync } from "node:fs";
import { expect, test } from "vitest";
import { admissionBindingV3, buildFSB3RequestV3, canonicalizeCandidatesV3, decodeArtifactV3JSON, encodeFSB3RequestV3 } from "./artifact.js";
import { claimConnectionLeaseV3, createArtifactLeaseV3Internal } from "./artifactLease.js";
import { selectTunnelIngress } from "./tunnelIngress.js";

const vectors = JSON.parse(readFileSync(new URL("../../../testdata/transport_v5/tunnel_pairing_vectors.json", import.meta.url), "utf8")) as {
  listeners: Record<"A" | "B", { url: string }>;
  legs: Record<"client" | "server", { artifact_json: string; candidate_id: string; fsb5_hex: string; admission_binding_hex: string; candidate_set_hash_b64u: string }>;
};

for (const [role, home, other] of [["client", "A", "B"], ["server", "B", "A"]] as const) {
  test(`${role} binds its admission to its own tunnel ingress`, () => {
    const vector = vectors.legs[role];
    const artifact = decodeArtifactV3JSON(vector.artifact_json);
    const lease = createArtifactLeaseV3Internal(artifact, async () => { throw new Error("unexpected spend"); });
    expect(() => claimConnectionLeaseV3(lease, vectors.listeners[other].url)).toThrowError(expect.objectContaining({ code: "tunnel_ingress_mismatch" }));
    expect(claimConnectionLeaseV3(lease, vectors.listeners[home].url)).toBeDefined();
    const candidates = canonicalizeCandidatesV3(artifact.path.kind, artifact.path.candidates);
    expect(candidates.hashBase64URL).toBe(vector.candidate_set_hash_b64u);
    const selected = selectTunnelIngress(artifact.path.kind, candidates.candidates, vectors.listeners[home].url);
    expect(selected.map(candidate => candidate.id)).toEqual([vector.candidate_id]);
    const frame = encodeFSB3RequestV3(buildFSB3RequestV3(artifact, selected[0]!.id));
    expect(Buffer.from(frame).toString("hex")).toBe(vector.fsb5_hex);
    expect(Buffer.from(admissionBindingV3(frame)).toString("hex")).toBe(vector.admission_binding_hex);
  });
}
