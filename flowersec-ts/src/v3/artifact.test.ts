import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import {
  ArtifactV3Error,
  acceptorAdmissionsHashV3,
  admissionBindingV3,
  buildFSB3RequestV3,
  canonicalizeCandidatesV3,
  computeSessionContractHashV3,
  decodeArtifactV3JSON,
  decodeFSA3ResponseV3,
  decodeFSB3RequestV3,
  encodeArtifactV3JSON,
  encodeFSA3ResponseV3,
  encodeFSB3RequestV3,
  tlsPolicyDigestV3,
  type AdmissionStatusV3,
  type TransportSecurityPolicyV3,
} from "./artifact.js";
import { snapshotTransportSecurityPolicyV3 } from "./security.js";

type Fixture = Readonly<{
  positive: readonly Positive[];
  negative: readonly Readonly<{ id: string; kind: "artifact_json"; value: string; error_code: string }>[];
  scalar_boundaries: readonly ArtifactBoundary[];
  scoped_payload_boundaries: readonly ArtifactBoundary[];
  artifact_byte_negative: readonly FrameNegative[];
  fsb3_negative: readonly FrameNegative[];
  fsa3_negative: readonly FrameNegative[];
  active_pin_snapshots: readonly Readonly<{
    id: string;
    attempt_now: number;
    declared: TransportSecurityPolicyV3;
    active_value_b64u: readonly string[];
    result: "attempt" | "tls_policy_expired";
  }>[];
  fsa3: readonly Readonly<{ status: 0 | 1 | 2; reason: string; frame_hex: string }>[];
}>;

type ArtifactBoundary = Readonly<{ id: string; accepted: boolean; artifact_json: string }>;
type FrameNegative = Readonly<{ id: string; value_hex: string; error_code: string }>;

type Positive = Readonly<{
  id: string;
  artifact_json: string;
  session_canonical_json: string;
  session_contract_hash_b64u: string;
  candidates_canonical_json: string;
  candidate_set_hash_b64u: string;
  tls_policy_digests: readonly Readonly<{
    candidate_id: string;
    canonical_json: string;
    digest_hex: string;
  }>[];
  winners: readonly Readonly<{
    candidate_id: string;
    fsb3_hex: string;
    admission_binding_hex: string;
  }>[];
  acceptor_admissions_hash_hex: string;
}>;

type IDNAFixture = Readonly<{
  unicode_version: "15.1.0";
  positive: readonly Readonly<{ id: string; input: string; ascii: string }>[];
  negative: readonly Readonly<{ id: string; input: string }>[];
  url_normalization: Readonly<{
    positive: readonly Readonly<{
      id: string;
      carrier: "raw_quic" | "websocket" | "webtransport";
      path_kind: "direct" | "tunnel";
      input: string;
      normalized: string;
      whatwg_roundtrip: boolean;
    }>[];
    negative: readonly Readonly<{
      id: string;
      carrier: "raw_quic" | "websocket" | "webtransport";
      path_kind: "direct" | "tunnel";
      input: string;
      error_code: "invalid_artifact";
    }>[];
  }>;
}>;

const fixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/artifact_vectors.json", import.meta.url),
  "utf8",
)) as Fixture;
const urlFixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/idna_vectors.json", import.meta.url),
  "utf8",
)) as IDNAFixture;
const goIssuerFixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/go_issuer_admission_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{
  artifact_json: string;
  chosen_candidate_id: string;
  fsb3_hex: string;
  admission_binding_hex: string;
  acceptor_admissions_hash_hex: string;
}>;
const hex = (value: Uint8Array): string => Buffer.from(value).toString("hex");
const fromHex = (value: string): Uint8Array => new Uint8Array(Buffer.from(value, "hex"));

describe("transport v3 artifact, TLS policy, and admission", () => {
  test("consumes the deterministic Go production issuer admission vector", () => {
    const artifact = decodeArtifactV3JSON(goIssuerFixture.artifact_json);
    const frame = encodeFSB3RequestV3(buildFSB3RequestV3(
      artifact,
      goIssuerFixture.chosen_candidate_id,
    ));
    expect(hex(frame)).toBe(goIssuerFixture.fsb3_hex);
    expect(hex(admissionBindingV3(frame))).toBe(goIssuerFixture.admission_binding_hex);
    expect(hex(acceptorAdmissionsHashV3(new Map([[goIssuerFixture.chosen_candidate_id, frame]]))))
      .toBe(goIssuerFixture.acceptor_admissions_hash_hex);
  });

  test("matches every canonical hash, FSB3, and admission vector", () => {
    for (const vector of fixture.positive) {
      const artifact = decodeArtifactV3JSON(vector.artifact_json);
      expect(new TextDecoder().decode(encodeArtifactV3JSON(artifact))).toBe(vector.artifact_json);
      const session = computeSessionContractHashV3(artifact.session);
      expect(session.canonicalJSON).toBe(vector.session_canonical_json);
      expect(session.hashBase64URL).toBe(vector.session_contract_hash_b64u);
      const candidates = canonicalizeCandidatesV3(artifact.path.kind, artifact.path.candidates);
      expect(candidates.canonicalJSON).toBe(vector.candidates_canonical_json);
      expect(candidates.hashBase64URL).toBe(vector.candidate_set_hash_b64u);

      for (const expected of vector.tls_policy_digests) {
        const candidate = candidates.candidates.find(({ id }) => id === expected.candidate_id)!;
        const digest = tlsPolicyDigestV3(candidate.tls);
        expect(digest.canonicalJSON).toBe(expected.canonical_json);
        expect(hex(digest.hash)).toBe(expected.digest_hex);
      }

      const admissions = new Map<string, Uint8Array>();
      for (const winner of vector.winners) {
        const frame = encodeFSB3RequestV3(buildFSB3RequestV3(artifact, winner.candidate_id));
        expect(hex(frame)).toBe(winner.fsb3_hex);
        expect(decodeFSB3RequestV3(frame).request.chosen_candidate_id).toBe(winner.candidate_id);
        expect(hex(admissionBindingV3(frame))).toBe(winner.admission_binding_hex);
        admissions.set(winner.candidate_id, frame);
      }
      expect(hex(acceptorAdmissionsHashV3(admissions))).toBe(vector.acceptor_admissions_hash_hex);
    }
  });

  test("rejects every shared invalid artifact as invalid_artifact", () => {
    for (const vector of fixture.negative) {
      expect(vector.kind).toBe("artifact_json");
      expect(() => decodeArtifactV3JSON(vector.value)).toThrowError(ArtifactV3Error);
      try {
        decodeArtifactV3JSON(vector.value);
      } catch (error) {
        expect((error as ArtifactV3Error).code, vector.id).toBe(vector.error_code);
      }
    }
  });

  test("executes every shared scalar and scoped-payload boundary", () => {
    for (const vector of [...fixture.scalar_boundaries, ...fixture.scoped_payload_boundaries]) {
      if (!vector.accepted) {
        expect(() => decodeArtifactV3JSON(vector.artifact_json), vector.id).toThrowError(ArtifactV3Error);
        continue;
      }
      const artifact = decodeArtifactV3JSON(vector.artifact_json);
      expect(new TextDecoder().decode(encodeArtifactV3JSON(artifact)), vector.id).toBe(vector.artifact_json);
    }
  });

  test("rejects shared invalid UTF-8, trailing bytes, and malformed admission frames", () => {
    for (const vector of fixture.artifact_byte_negative) {
      expect(() => decodeArtifactV3JSON(fromHex(vector.value_hex)), vector.id).toThrowError(ArtifactV3Error);
    }
    for (const vector of fixture.fsb3_negative) {
      expect(() => decodeFSB3RequestV3(fromHex(vector.value_hex)), vector.id).toThrowError(ArtifactV3Error);
    }
    for (const vector of fixture.fsa3_negative) {
      expect(() => decodeFSA3ResponseV3(fromHex(vector.value_hex)), vector.id).toThrowError(ArtifactV3Error);
    }
  });

  test("consumes every shared v3 URL normalization vector through artifact decoding", () => {
    for (const vector of urlFixture.url_normalization.positive) {
      const artifact = decodeArtifactV3JSON(artifactJSONWithCandidateURL(
        vector.path_kind,
        vector.carrier,
        vector.input,
      ));
      expect(artifact.path.candidates, vector.id).toHaveLength(1);
      expect(artifact.path.candidates[0]?.normalized_url, vector.id).toBe(vector.normalized);
    }

    for (const vector of urlFixture.url_normalization.negative) {
      expect(
        () => decodeArtifactV3JSON(artifactJSONWithCandidateURL(
          vector.path_kind,
          vector.carrier,
          vector.input,
        )),
        vector.id,
      ).toThrowError(expect.objectContaining({ code: vector.error_code }));
    }
  });

  test("consumes every frozen root IDNA vector through artifact decoding", () => {
    expect(urlFixture.unicode_version).toBe("15.1.0");
    for (const vector of urlFixture.positive) {
      const artifact = decodeArtifactV3JSON(artifactJSONWithCandidateURL(
        "direct",
        "websocket",
        `wss://${vector.input}/flowersec/v3/direct`,
      ));
      expect(artifact.path.candidates[0]?.normalized_url, vector.id)
        .toBe(`wss://${vector.ascii}/flowersec/v3/direct`);
    }
    for (const vector of urlFixture.negative) {
      expect(
        () => decodeArtifactV3JSON(artifactJSONWithCandidateURL(
          "direct",
          "websocket",
          `wss://${vector.input}/flowersec/v3/direct`,
        )),
        vector.id,
      ).toThrowError(expect.objectContaining({ code: "invalid_artifact" }));
    }
  });

  test("takes one exclusive active-pin snapshot per attempt", () => {
    for (const vector of fixture.active_pin_snapshots) {
      if (vector.result === "tls_policy_expired") {
        expect(vector.active_value_b64u, vector.id).toEqual([]);
        expect(() => snapshotTransportSecurityPolicyV3(vector.declared, vector.attempt_now, ["pin"]))
          .toThrowError(expect.objectContaining({ code: vector.result }));
        continue;
      }
      const snapshot = snapshotTransportSecurityPolicyV3(vector.declared, vector.attempt_now, ["pin"]);
      expect(snapshot.mode, vector.id).toBe("pin");
      if (snapshot.mode === "pin") {
        expect(snapshot.activePins.map(({ value_b64u }) => value_b64u), vector.id)
          .toEqual(vector.active_value_b64u);
      }
    }
  });

  test("matches FSA3 and rejects cross-version frames", () => {
    for (const vector of fixture.fsa3) {
      const status = vector.status as AdmissionStatusV3;
      const reasons = new Set(vector.reason === "" ? [] : [vector.reason]);
      const frame = encodeFSA3ResponseV3({ status, reason: vector.reason }, reasons);
      expect(hex(frame)).toBe(vector.frame_hex);
      expect(decodeFSA3ResponseV3(frame)).toEqual({ status, reason: vector.reason });
      const v2 = frame.slice();
      v2[3] = 0x32;
      v2[4] = 2;
      expect(() => decodeFSA3ResponseV3(v2)).toThrowError(ArtifactV3Error);
    }
  });

  test("keeps client reason decoding registry-free and enforces the server registry", () => {
    const registered = encodeFSA3ResponseV3(
      { status: 1 as AdmissionStatusV3, reason: "policy_denied" },
      new Set(["policy_denied"]),
    );
    expect(decodeFSA3ResponseV3(registered)).toEqual({ status: 1, reason: "policy_denied" });
    expect(() => encodeFSA3ResponseV3(
      { status: 1 as AdmissionStatusV3, reason: "policy_denied" },
    )).toThrowError(ArtifactV3Error);
    expect(() => encodeFSA3ResponseV3(
      { status: 1 as AdmissionStatusV3, reason: "tls_pin_mismatch" },
      new Set(["tls_pin_mismatch"]),
    )).toThrowError(ArtifactV3Error);

    const peerOnly = registered.slice();
    const reason = new TextEncoder().encode("unknown_reason");
    const unknownFrame = new Uint8Array(8 + reason.length);
    unknownFrame.set(peerOnly.subarray(0, 8));
    new DataView(unknownFrame.buffer).setUint16(6, reason.length, false);
    unknownFrame.set(reason, 8);
    expect(decodeFSA3ResponseV3(unknownFrame)).toEqual({ status: 1, reason: "unknown_reason" });
    expect(() => decodeFSA3ResponseV3(
      Uint8Array.from([0x46, 0x53, 0x41, 0x33, 3, 1, 0, 16,
        ...new TextEncoder().encode("expired_artifact")]),
    )).toThrowError(ArtifactV3Error);
    expect(() => encodeFSA3ResponseV3(
      { status: 1, reason: "expired_artifact" },
      new Set(["expired_artifact"]),
    )).toThrowError(ArtifactV3Error);
  });
});

function artifactJSONWithCandidateURL(
  pathKind: "direct" | "tunnel",
  carrier: "raw_quic" | "websocket" | "webtransport",
  url: string,
): string {
  const source = fixture.positive.find(({ artifact_json }) =>
    (JSON.parse(artifact_json) as { path: { kind: string } }).path.kind === pathKind);
  if (source === undefined) throw new Error(`missing ${pathKind} artifact vector`);
  const artifact = JSON.parse(source.artifact_json) as {
    path: {
      candidates: Array<{
        carrier: string;
        url: string;
      }>;
    };
  };
  const candidate = artifact.path.candidates.find((item) => item.carrier === carrier);
  if (candidate === undefined) throw new Error(`missing ${pathKind} ${carrier} candidate vector`);
  candidate.url = url;
  artifact.path.candidates = [candidate];
  return JSON.stringify(artifact);
}
