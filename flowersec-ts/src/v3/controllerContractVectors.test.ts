import { readFileSync } from "node:fs";
import { describe, expect, test, vi } from "vitest";

import {
  artifactLeaseStateV3,
  claimArtifactLeaseV3,
  commitArtifactLeaseSpendV3,
  createArtifactLeaseV3Internal,
  retireArtifactLeaseV3,
} from "./artifactLease.js";
import { canonicalizeCandidatesV3, decodeArtifactV3JSON } from "./artifact.js";
import { aggregateCandidateFailuresV3 } from "./controller.js";
import {
  TransportFailureV3,
  aggregateRetryDispositionsV3,
  projectTransportFailureV3,
  validateRetryDispositionV3,
  type TransportFailureCodeV3,
  type TransportFailureDetailV3,
} from "./security.js";

type InternalTransportResult = readonly [
  TransportFailureCodeV3,
  TransportFailureDetailV3 | null,
  string,
];

type ControllerContractFixture = Readonly<{
  internal_transport_results: readonly InternalTransportResult[];
  retry_after: Readonly<{
    valid: readonly number[];
    invalid: readonly unknown[];
    aggregate: string;
  }>;
  lease_state_machine: Readonly<{
    states: readonly string[];
    transitions: readonly (readonly [string, string, string])[];
    terminal_states: readonly string[];
  }>;
}>;

const fixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/controller_vectors.json", import.meta.url),
  "utf8",
)) as ControllerContractFixture;
const artifactVector = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/artifact_vectors.json", import.meta.url),
  "utf8",
)).positive[0] as { artifact_json: string };
const artifact = decodeArtifactV3JSON(artifactVector.artifact_json);
const candidates = canonicalizeCandidatesV3(artifact.path.kind, artifact.path.candidates).candidates;
const caCandidate = candidates.find(({ tls }) => tls.mode === "ca")!;
const pinCandidate = candidates.find(({ tls }) => tls.mode === "pin")!;

describe("transport v3 top-level controller contract vectors", () => {
  test("binds every internal result tuple to production aggregation and projection", () => {
    const expectedActions = new Map<string, string>([
      ["invalid_artifact/", "terminal"],
      ["expired_artifact/", "acquire_primary"],
      ["tls_unsupported/", "skip_candidate"],
      ["tls_policy_expired/", "policy_refresh"],
      ["tls_failed/ca_untrusted", "candidate_terminal"],
      ["tls_failed/pin_mismatch", "policy_refresh"],
      ["tls_failed/unknown", "policy_refresh_for_pin"],
      ["connection_failed/browser_pin_opaque", "policy_sensitive_replacement"],
    ]);
    const seen = new Set<string>();
    for (const [code, detail, action] of fixture.internal_transport_results) {
      const key = `${code}/${detail ?? ""}`;
      expect(action, key).toBe(expectedActions.get(key));
      expect(seen.has(key), `duplicate ${key}`).toBe(false);
      seen.add(key);

      const candidate = detail === "ca_untrusted" ? caCandidate : pinCandidate;
      const failure = new TransportFailureV3(code, detail ?? undefined);
      const policyRefreshExecutable = action === "policy_refresh" ||
        action === "policy_refresh_for_pin" || action === "policy_sensitive_replacement";
      const aggregate = aggregateCandidateFailuresV3(
        [{ candidate, failure }],
        policyRefreshExecutable,
      );
      if (policyRefreshExecutable) {
        expect(aggregate, key).toBe("policy_refresh");
      } else {
        const expectedCode = code === "invalid_artifact"
          ? "artifact_invalid"
          : code === "expired_artifact"
            ? "expired_artifact"
            : code === "tls_unsupported"
              ? "transport_security_unsupported"
              : code === "tls_failed"
                ? "transport_security_failed"
                : "connection_failed";
        expect(aggregate, key).toMatchObject({ code: expectedCode });
      }

      const projected = projectTransportFailureV3(failure, candidate.tls.mode);
      const projectionRetryable = code === "expired_artifact" || code === "connection_failed";
      expect(projected.disposition.kind, key).toBe(projectionRetryable ? "retryable" : "terminal");
    }
    expect(seen).toEqual(new Set(expectedActions.keys()));
  });

  test("executes retry-after boundaries and the complete lease transition table", async () => {
    expect(fixture.retry_after.aggregate).toBe("maximum_absolute_unix_ms");
    for (const value of fixture.retry_after.valid) {
      expect(validateRetryDispositionV3({
        kind: "retry_after",
        absoluteUnixMilliseconds: value,
      })).toEqual({ kind: "retry_after", absoluteUnixMilliseconds: value });
    }
    for (const value of fixture.retry_after.invalid) {
      expect(() => validateRetryDispositionV3({
        kind: "retry_after",
        absoluteUnixMilliseconds: value as number,
      })).toThrow();
    }
    expect(aggregateRetryDispositionsV3(fixture.retry_after.valid.map((value) => ({
      kind: "retry_after" as const,
      absoluteUnixMilliseconds: value,
    })))).toEqual({
      kind: "retry_after",
      absoluteUnixMilliseconds: 253_402_300_799_999,
    });

    expect(fixture.lease_state_machine).toEqual({
      states: ["idle", "claimed", "spending", "consumed", "retired"],
      transitions: [
        ["idle", "claimed", "claim"],
        ["claimed", "spending", "commitSpend"],
        ["spending", "consumed", "durable_result"],
        ["claimed", "retired", "retire"],
      ],
      terminal_states: ["consumed", "retired"],
    });

    let markSpendStarted!: () => void;
    const spendStarted = new Promise<void>((resolve) => { markSpendStarted = resolve; });
    let finishSpend!: () => void;
    const spendFinished = new Promise<void>((resolve) => { finishSpend = resolve; });
    const spend = vi.fn(async () => {
      markSpendStarted();
      await spendFinished;
    });
    const spendingLease = createArtifactLeaseV3Internal(artifact, spend);
    expect(artifactLeaseStateV3(spendingLease)).toBe("idle");
    const spendingClaim = claimArtifactLeaseV3(spendingLease);
    expect(artifactLeaseStateV3(spendingClaim)).toBe("claimed");
    const commit = commitArtifactLeaseSpendV3(spendingClaim);
    await spendStarted;
    expect(artifactLeaseStateV3(spendingClaim)).toBe("spending");
    finishSpend();
    await commit;
    expect(artifactLeaseStateV3(spendingClaim)).toBe("consumed");
    expect(spend).toHaveBeenCalledOnce();

    const cleanup = vi.fn(async () => undefined);
    const retiringLease = createArtifactLeaseV3Internal(artifact, async () => undefined, cleanup);
    const retiringClaim = claimArtifactLeaseV3(retiringLease);
    await retireArtifactLeaseV3(retiringClaim);
    expect(artifactLeaseStateV3(retiringClaim)).toBe("retired");
    expect(cleanup).toHaveBeenCalledOnce();
  });
});
