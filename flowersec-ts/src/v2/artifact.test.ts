import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import {
  AdmissionStatusV2,
  admissionBindingV2,
  buildFSB2RequestV2,
  canonicalizeCandidatesV2,
  computeSessionContractHashV2,
  decodeArtifactV2JSON,
  decodeFSA2ResponseV2,
  decodeFSB2RequestV2,
  encodeArtifactV2JSON,
  encodeFSA2ResponseV2,
  encodeFSB2RequestV2,
  type ArtifactCandidateV2,
  type ArtifactV2Error,
  type ArtifactV2,
  type DirectArtifactPathV2,
} from "./artifact.js";

type ArtifactVectorFixture = Readonly<{
  version: number;
  profile: string;
  source: Readonly<{ producer: string; go: string; command: string }>;
  positive: readonly PositiveArtifactVector[];
  fsa2: readonly FSA2Vector[];
  negative: readonly NegativeArtifactVector[];
}>;

type PositiveArtifactVector = Readonly<{
  id: string;
  path_kind: "direct" | "tunnel";
  artifact_json: string;
  session_canonical_json: string;
  session_contract_hash_b64u: string;
  candidates_canonical_json: string;
  candidate_set_hash_b64u: string;
  winners: readonly Readonly<{
    candidate_id: string;
    fsb2_hex: string;
    admission_binding_hex: string;
  }>[];
}>;

type FSA2Vector = Readonly<{
  id: string;
  status: 0 | 1 | 2;
  reason: string;
  frame_hex: string;
}>;

type NegativeArtifactVector = Readonly<{
  id: string;
  kind: "artifact_json" | "fsb2_hex" | "fsa2_hex";
  value: string;
  error_code: string;
}>;

type IDNAVectorFixture = Readonly<{
  unicode_version: string;
  positive: readonly Readonly<{ id: string; input: string; ascii: string }>[];
  negative: readonly Readonly<{ id: string; input: string }>[];
}>;

const fixture = JSON.parse(
  readFileSync(new URL("../../../testdata/transport_v2/artifact_vectors.json", import.meta.url), "utf8"),
) as ArtifactVectorFixture;
const reasons = new Set(["capacity", "invalid_token"]);
const idnaFixture = JSON.parse(
  readFileSync(new URL("../../../testdata/transport_v2/idna_vectors.json", import.meta.url), "utf8"),
) as IDNAVectorFixture;

describe("transport v2 artifact and admission vectors", () => {
  test("consumes Go-produced artifact, labeled hash, and every-winner FSB2 vectors", () => {
    expect(fixture.version).toBe(1);
    expect(fixture.profile).toBe("flowersec/2");
    expect(fixture.source.producer).toBe("flowersec-go/internal/artifactv2");
    expect(fixture.positive).toHaveLength(2);

    for (const vector of fixture.positive) {
      const artifact = decodeArtifactV2JSON(vector.artifact_json);
      expect(artifact.v).toBe(2);
      expect(artifact.profile).toBe("flowersec/2");
      expect(artifact.path.kind).toBe(vector.path_kind);
      expect(new TextDecoder().decode(encodeArtifactV2JSON(artifact))).toBe(vector.artifact_json);

      const session = computeSessionContractHashV2(artifact.session);
      expect(session.canonicalJSON).toBe(vector.session_canonical_json);
      expect(session.hashBase64URL).toBe(vector.session_contract_hash_b64u);

      const candidates = canonicalizeCandidatesV2(artifact.path.kind, artifact.path.candidates);
      expect(candidates.canonicalJSON).toBe(vector.candidates_canonical_json);
      expect(candidates.hashBase64URL).toBe(vector.candidate_set_hash_b64u);
      expect(candidates.candidates.map((candidate) => candidate.id)).toEqual(["q1", "t1", "w1"]);
      expect(candidates.candidates.map((candidate) => candidate.carrier)).toEqual([
        "raw_quic",
        "webtransport",
        "websocket",
      ]);

      for (const winner of vector.winners) {
        const request = buildFSB2RequestV2(artifact, winner.candidate_id);
        const encoded = encodeFSB2RequestV2(request);
        expect(hex(encoded), `${vector.id}/${winner.candidate_id}`).toBe(winner.fsb2_hex);
        expect(hex(admissionBindingV2(encoded))).toBe(winner.admission_binding_hex);

        const decoded = decodeFSB2RequestV2(encoded);
        expect(decoded.request.pathKind).toBe(vector.path_kind);
        expect(decoded.request.chosen_candidate_id).toBe(winner.candidate_id);
        expect(hex(decoded.raw)).toBe(winner.fsb2_hex);
        expect(hex(decoded.localAdmissionBinding)).toBe(winner.admission_binding_hex);
      }
    }
  });

  test("consumes the shared negative artifact, FSB2, and FSA2 vectors", () => {
    for (const vector of fixture.negative) {
      const operation = () => {
        switch (vector.kind) {
          case "artifact_json":
            return decodeArtifactV2JSON(vector.value);
          case "fsb2_hex":
            return decodeFSB2RequestV2(fromHex(vector.value));
          case "fsa2_hex":
            return decodeFSA2ResponseV2(fromHex(vector.value), reasons);
        }
      };
      expect(operation, vector.id).toThrowError(
        expect.objectContaining<Partial<ArtifactV2Error>>({ code: vector.error_code }),
      );
    }
  });

  test("rejects oversized FSB2 from the header before requiring or slicing payload bytes", () => {
    const vector = fixture.negative.find((item) => item.id === "fsb2-oversized-declared-length");
    expect(vector).toBeDefined();
    const headerOnly = fromHex(vector!.value);
    expect(headerOnly).toHaveLength(12);
    expect(() => decodeFSB2RequestV2(headerOnly)).toThrowError(
      expect.objectContaining({ code: "fsb2_payload_too_large" }),
    );
  });

  test("matches FSA2 statuses and enforces the audited reason registry", () => {
    for (const vector of fixture.fsa2) {
      const response = {
        status: vector.status as AdmissionStatusV2,
        reason: vector.reason,
      };
      expect(hex(encodeFSA2ResponseV2(response, reasons)), vector.id).toBe(vector.frame_hex);
      expect(decodeFSA2ResponseV2(fromHex(vector.frame_hex), reasons)).toEqual(response);
    }

    expect(() =>
      encodeFSA2ResponseV2(
        { status: AdmissionStatusV2.Reject, reason: "not_audited" },
        reasons,
      ),
    ).toThrowError(expect.objectContaining({ code: "unknown_admission_reason" }));
    expect(() =>
      encodeFSA2ResponseV2(
        { status: AdmissionStatusV2.Success, reason: "invalid_token" },
        reasons,
      ),
    ).toThrowError(expect.objectContaining({ code: "invalid_fsa2" }));
  });

  test("enforces candidate count, exact registry values, tuples, schemes, paths, and profiles", () => {
    const direct = directArtifact();
    expectArtifactError(withDirectCandidates(direct, []), "invalid_candidate");

    const base = direct.path.candidates[0]!;
    const five = [
      ...direct.path.candidates,
      { ...base, id: "w2", url: "wss://two.example/flowersec/v2/direct" },
      { ...base, id: "w3", url: "wss://three.example/flowersec/v2/direct" },
    ];
    expectArtifactError(withDirectCandidates(direct, five), "invalid_candidate");

    const duplicateTuple = direct.path.candidates.map((candidate) =>
      candidate.id === "t1" ? { ...base, id: "w2" } : candidate,
    );
    expectArtifactError(withDirectCandidates(direct, duplicateTuple), "invalid_candidate");

    for (const candidate of [
      { ...base, carrier: "quic" as ArtifactCandidateV2["carrier"] },
      { ...base, wire_profile: "flowersec-tunnel/2" },
      { ...base, url: "https://example.com/flowersec/v2/direct" },
      { ...base, url: "wss://example.com/flowersec/v2/tunnel" },
      { ...base, url: "wss://example.com./flowersec/v2/direct" },
      { ...base, url: "wss://192.168.001.1/flowersec/v2/direct" },
      { ...base, url: "wss://example.com/flowersec/v2/direct?" },
    ]) {
      expectArtifactError(withDirectCandidates(direct, [candidate]), "invalid_candidate");
    }
  });

  test("preflights the canonical FSB2 payload for every possible winner", () => {
    const direct = directArtifact();
    const oversized: ArtifactV2 = {
      ...direct,
      path: {
        ...direct.path,
        routing_token: "\u0001".repeat(6_000),
      },
    };
    expect(() => encodeArtifactV2JSON(oversized)).toThrowError(
      expect.objectContaining({ code: "fsb2_payload_too_large" }),
    );
  });

  test("normalizes Unicode 15.1 UTS #46 hosts to lowercase A-labels", () => {
    expect(idnaFixture.unicode_version).toBe("15.1.0");
    for (const { input: host, ascii: want } of idnaFixture.positive) {
      const candidates = canonicalizeCandidatesV2("direct", [
        {
          id: "w1",
          carrier: "websocket",
          url: `wss://${host}/flowersec/v2/direct`,
          wire_profile: "flowersec-direct/2",
        },
      ]);
      expect(candidates.candidates[0]?.normalized_url).toBe(
        `wss://${want}/flowersec/v2/direct`,
      );
    }
  });

  test("rejects invalid Unicode 15.1 UTS #46 hosts", () => {
    for (const { input: host } of idnaFixture.negative) {
      expect(() =>
        canonicalizeCandidatesV2("direct", [
          {
            id: "w1",
            carrier: "websocket",
            url: `wss://${host}/flowersec/v2/direct`,
            wire_profile: "flowersec-direct/2",
          },
        ]),
      ).toThrowError(expect.objectContaining({ code: "invalid_candidate" }));
    }
  });

  test("does not route Artifact v2 through the v1 artifact or business-connect layer", () => {
    const source = readFileSync(new URL("./artifact.ts", import.meta.url), "utf8");
    expect(source).not.toContain("../connect/artifact");
    expect(source).not.toContain("ConnectArtifact");
    expect(source).not.toContain("tenant_id");
    expect(source).not.toContain("environment_id");
    expect(source).not.toContain("provider_id");
  });
});

function directArtifact(): ArtifactV2 & Readonly<{ path: DirectArtifactPathV2 }> {
  const vector = fixture.positive.find((item) => item.path_kind === "direct");
  expect(vector).toBeDefined();
  const artifact = decodeArtifactV2JSON(vector!.artifact_json);
  if (artifact.path.kind !== "direct") throw new Error("fixture path drifted");
  return artifact;
}

function withDirectCandidates(
  artifact: ArtifactV2 & Readonly<{ path: DirectArtifactPathV2 }>,
  candidates: readonly ArtifactCandidateV2[],
): ArtifactV2 {
  return {
    ...artifact,
    path: {
      ...artifact.path,
      candidates,
    },
  };
}

function expectArtifactError(artifact: ArtifactV2, code: string): void {
  expect(() => encodeArtifactV2JSON(artifact)).toThrowError(
    expect.objectContaining({ code }),
  );
}

function fromHex(value: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})*$/.test(value)) throw new Error("invalid fixture hex");
  return Uint8Array.from(value.match(/../g)?.map((byte) => Number.parseInt(byte, 16)) ?? []);
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
